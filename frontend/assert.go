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

	"github.com/stretchr/testify/require"
)

// Assert is a helper to test circuits
type Assert struct {
	t *testing.T
	*require.Assertions
}

// NewAssert returns an helper to test Constraint Systems
// this helper embeds a stretch/testify Assert object for convenience
func NewAssert(t *testing.T) *Assert {
	return &Assert{t, require.New(t)}
}

// -------------------------------------------------------------------------------------------------
// internal

type expectedCS struct {
	nbWires, nbMOConstraints, nbNOConstraints int
	nbConstraints                             uint64
}

type expectedR1CS struct {
	nbWires, nbComputationalConstraints, nbConstraints, nbPrivateWires, nbPublicWires int
}

func (assert *Assert) csIsCorrect(circuit CS, expectedCS expectedCS) {
	assert.Equal(expectedCS.nbWires, circuit.countWires(), "cs nbWires")
	assert.Equal(expectedCS.nbConstraints, circuit.nbConstraints, "cs nbConstraints")
	assert.Equal(expectedCS.nbMOConstraints, len(circuit.MOConstraints), "cs nb MOConstraints")
	assert.Equal(expectedCS.nbNOConstraints, len(circuit.NOConstraints), "cs nb NOConstraints")
}

func (assert *Assert) r1csIsCorrect(circuit CS, expectedR1CS expectedR1CS) {
	r1cs := circuit.ToR1CS()
	assert.Equal(expectedR1CS.nbWires, r1cs.NbWires, "r1cs nbWires")
	assert.Equal(expectedR1CS.nbPrivateWires, r1cs.NbPrivateWires, "r1cs private nbWires")
	assert.Equal(expectedR1CS.nbPublicWires, r1cs.NbPublicWires, "r1cs public nbWires")
	assert.Equal(expectedR1CS.nbConstraints, r1cs.NbConstraints, "r1cs nbConstraints")
	assert.Equal(expectedR1CS.nbComputationalConstraints, r1cs.NbCOConstraints, "r1cs computational nbConstraints")
}

func (assert *Assert) errInputNotSet(circuit CS) {
	// r := circuit.ToR1CS()

	// nbInputs := r.NbPrivateWires + r.NbPublicWires - 1
	// if nbInputs > 0 {
	// 	wireValues := make([]fr.Element, r.NbWires)
	// 	a := make([]fr.Element, r.NbConstraints)
	// 	b := make([]fr.Element, r.NbConstraints)
	// 	c := make([]fr.Element, r.NbConstraints)
	// 	err := r.Solve(backend.NewAssignment(), a, b, c, wireValues)
	// 	assert.Error(err, "solving R1CS without assignments should return an error")
	// 	assert.True(errors.Is(err, backend.ErrInputNotSet), "expected ErrInputNotSet, got %v", err)
	// }
}
