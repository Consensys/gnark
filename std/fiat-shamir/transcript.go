/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fiatshamir

import (
	"errors"
	"github.com/consensys/gnark/constant"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// errChallengeNotFound is returned when a wrong challenge name is provided.
var (
	errChallengeNotFound            = errors.New("challenge not recorded in the Transcript")
	errChallengeAlreadyComputed     = errors.New("challenge already computed, cannot be binded to other values")
	errPreviousChallengeNotComputed = errors.New("the previous challenge is needed and has not been computed")
)

// Transcript handles the creation of challenges for Fiat Shamir.
type Transcript struct {
	// hash function that is used.
	h hash.Hash

	challenges map[string]challenge
	previous   *challenge

	// gnark API
	api frontend.API
}

type challenge struct {
	position   int                 // position of the challenge in the transcript. order matters.
	bindings   []frontend.Variable // bindings stores the variables a challenge is binded to.
	value      frontend.Variable   // value stores the computed challenge
	isComputed bool
}

// NewTranscript returns a new transcript.
// h is the hash function that is used to compute the challenges.
// challenges are the name of the challenges. The order is important.
func NewTranscript(api frontend.API, h hash.Hash, challengesID ...string) Transcript {
	n := len(challengesID)
	t := Transcript{
		challenges: make(map[string]challenge, n),
		api:        api,
		h:          h,
	}

	for i := 0; i < n; i++ {
		t.challenges[challengesID[i]] = challenge{position: i}
	}

	return t
}

// Bind binds the challenge to value. A challenge can be binded to an
// arbitrary number of values, but the order in which the binded values
// are added is important. Once a challenge is computed, it cannot be
// binded to other values.
func (t *Transcript) Bind(challengeID string, values []frontend.Variable) error {

	challenge, ok := t.challenges[challengeID]

	if !ok {
		return errChallengeNotFound
	}
	if challenge.isComputed {
		return errChallengeAlreadyComputed
	}

	challenge.bindings = append(challenge.bindings, values...)
	t.challenges[challengeID] = challenge

	return nil

}

// ComputeChallenge computes the challenge corresponding to the given name.
// The resulting variable is:
// * H(name ∥ previous_challenge ∥ binded_values...) if the challenge is not the first one
// * H(name ∥ binded_values... ) if it's is the first challenge
func (t *Transcript) ComputeChallenge(challengeID string) (frontend.Variable, error) {

	challenge, ok := t.challenges[challengeID]

	if !ok {
		return nil, errChallengeNotFound
	}

	// if the challenge was already computed we return it
	if challenge.isComputed {
		return challenge.value, nil
	}

	t.h.Reset()

	// write the challenge name, the purpose is to have a domain separator
	cChallenge := []byte(challengeID) // if we send a string, it is assumed to be a base10 number
	if challengeName, err := constant.HashedBytes(t.api, cChallenge); err == nil {
		t.h.Write(challengeName)
	} else {
		return nil, err
	}

	// write the previous challenge if it's not the first challenge
	if challenge.position != 0 {
		if t.previous == nil || (t.previous.position != challenge.position-1) {
			return nil, errPreviousChallengeNotComputed
		}
		t.h.Write(t.previous.value)
	}

	// write the binded values in the order they were added
	t.h.Write(challenge.bindings...)

	// compute the hash of the accumulated values
	challenge.value = t.h.Sum()
	challenge.isComputed = true
	t.previous = &challenge

	t.challenges[challengeID] = challenge

	t.h.Reset()

	return challenge.value, nil

}
