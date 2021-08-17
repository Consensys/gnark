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

	// stores the current round number. Each time a challenge is generated,
	// the round variable is incremented.
	nbChallenges int

	// challengeOrder maps the challenge's name to a number corresponding to its order.
	challengeOrder map[string]int

	// bindings stores the variables a challenge is binded to.
	// The i-th entry stores the variables to which the i-th challenge is binded to.
	bindings [][]frontend.Variable

	// challenges stores the computed challenges. The i-th entry stores the i-th computed challenge.
	challenges []frontend.Variable

	// boolean table telling if the i-th challenge has been computed.
	isComputed []bool

	// hash function that is used.
	h hash.Hash

	// underlying constraint system
	cs *frontend.ConstraintSystem
}

// NewTranscript returns a new transcript.
// h is the hash function that is used to compute the challenges.
// challenges are the name of the challenges. The order is important.
func NewTranscript(cs *frontend.ConstraintSystem, h hash.Hash, challenges ...string) Transcript {

	var res Transcript

	res.nbChallenges = len(challenges)

	res.challengeOrder = make(map[string]int)
	for i := 0; i < len(challenges); i++ {
		res.challengeOrder[challenges[i]] = i
	}

	res.bindings = make([][]frontend.Variable, res.nbChallenges)
	res.challenges = make([]frontend.Variable, res.nbChallenges)
	for i := 0; i < res.nbChallenges; i++ {
		res.bindings[i] = make([]frontend.Variable, 0)
	}

	res.isComputed = make([]bool, res.nbChallenges)

	res.h = h

	res.cs = cs

	return res
}

// Bind binds the challenge to value. A challenge can be binded to an
// arbitrary number of values, but the order in which the binded values
// are added is important. Once a challenge is computed, it cannot be
// binded to other values.
func (m *Transcript) Bind(challenge string, value []frontend.Variable) error {

	challengeNumber, ok := m.challengeOrder[challenge]

	if !ok {
		return errChallengeNotFound
	}

	if m.isComputed[challengeNumber] {
		return errChallengeAlreadyComputed
	}
	m.bindings[challengeNumber] = append(m.bindings[challengeNumber], value...)

	return nil

}

// ComputeChallenge computes the challenge corresponding to the given name.
// The resulting variable is:
// * H(name || previous_challenge || binded_values...) if the challenge is not the first one
// * H(name || binded_values... ) if it's is the first challenge
func (m *Transcript) ComputeChallenge(challenge string) (frontend.Variable, error) {

	challengeNumber, ok := m.challengeOrder[challenge]
	if !ok {
		return frontend.Variable{}, errChallengeNotFound
	}

	// if the challenge was already computed we return it
	if m.isComputed[challengeNumber] {
		return m.challenges[challengeNumber], nil
	}

	m.h.Reset()

	// write the challenge name, the purpose is to have a domain separator
	cChallenge := m.cs.Constant([]byte(challenge))
	m.h.Write(cChallenge)

	// write the previous challenge if it's not the first challenge
	if challengeNumber != 0 {
		if !m.isComputed[challengeNumber-1] {
			return frontend.Variable{}, errPreviousChallengeNotComputed
		}
		bPreviousChallenge := m.challenges[challengeNumber-1]
		m.h.Write(bPreviousChallenge)
	}

	// write the binded values in the order they were added
	m.h.Write(m.bindings[challengeNumber]...)

	// compute the hash of the accumulated values
	res := m.h.Sum()

	// record the computation
	m.challenges[challengeNumber] = res
	m.isComputed[challengeNumber] = true

	return res, nil

}
