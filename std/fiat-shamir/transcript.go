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

import "github.com/consensys/gnark/std/hash"

// Transcript handles the creation of challenges for Fiat Shamir.
type Transcript struct {

	// stores the current round number. Each time a challenge is generated,
	// the round variable is incremented.
	nbChallenges int

	// challengeOrder maps the challenge's name to a number corresponding to its order.
	challengeOrder map[string]int

	// bindings stores the variables a challenge is binded to.
	// The i-th entry stores the variables to which the i-th challenge is binded to.
	bindings [][]byte

	// challenges stores the computed challenges. The i-th entry stores the i-th computed challenge.
	challenges [][]byte

	// boolean table telling if the i-th challenge has been computed.
	isComputed []bool

	// hash function that is used.
	h hash.Hash
}
