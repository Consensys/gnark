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

package frontend

import (
	"testing"

	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gurvy"
	"github.com/stretchr/testify/require"
)

// Assert is a helper to test circuits
type Assert struct {
	t *testing.T
	*require.Assertions
}

// newAssert returns an helper to test Constraint Systems
// this helper embeds a stretch/testify Assert object for convenience
func newAssert(t *testing.T) *Assert {
	return &Assert{t, require.New(t)}
}

// -------------------------------------------------------------------------------------------------
// internal

type expectedCS struct {
	nbWires, nbMOConstraints, nbNOConstraints int
	nbConstraints                             int
}

type expectedR1CS struct {
	nbWires, nbComputationalConstraints, nbConstraints, nbSecretWires, nbPublicWires int
}

// func (assert *Assert) csIsCorrect(circuit CS, expectedCS expectedCS) {
// 	//assert.Equal(expectedCS.nbWires, circuit.countWires(), "cs nbWires")
// 	assert.Equal(expectedCS.nbConstraints, circuit.nbConstraints(), "cs nbConstraints")
// 	assert.Equal(expectedCS.nbMOConstraints, len(circuit.moExpressions), "cs nb MOConstraints")
// 	assert.Equal(expectedCS.nbNOConstraints, len(circuit.noExpressions), "cs nb NOConstraints")
// }

func (assert *Assert) r1csIsCorrect(circuit CS, expectedR1CS expectedR1CS) {
	_r1cs := circuit.toR1cs(gurvy.UNKNOWN)
	r1cs := _r1cs.(*r1cs.UntypedR1CS)
	assert.Equal(expectedR1CS.nbWires, r1cs.NbWires, "r1cs nbWires")
	assert.Equal(expectedR1CS.nbSecretWires, r1cs.NbSecretWires, "r1cs private nbWires")
	assert.Equal(expectedR1CS.nbPublicWires, r1cs.NbPublicWires, "r1cs public nbWires")
	assert.Equal(expectedR1CS.nbConstraints, r1cs.NbConstraints, "r1cs nbConstraints")
	assert.Equal(expectedR1CS.nbComputationalConstraints, r1cs.NbCOConstraints, "r1cs computational nbConstraints")
}

// // util function to count the wires of a constraint system
// func (cs *CS) countWires() int {

// 	var wires []int

// 	for cID, c := range cs.constraints {
// 		if cID == 0 {
// 			continue // skipping first entry, reserved
// 		}
// 		isCounted := false
// 		for _, w := range wires {
// 			if w == c.ID {
// 				isCounted = true
// 				continue
// 			}
// 		}
// 		if !isCounted {
// 			wires = append(wires, c.ID)
// 		}
// 	}

// 	return len(wires)
// }
