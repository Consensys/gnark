// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package groth16

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

// Assert is a helper to test circuits
type Assert struct {
	*require.Assertions
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

// ProverFailed check that a solution does NOT solve a circuit
// error may be missing inputs or unsatisfied constraints
// it creates a groth16.ProvingKey for the r1cs
// run groth16.Prove (which solves the R1CS) and expects an error
// provided _solution must either implements frontend.Circuit or be
// a map[string]interface{}
func (assert *Assert) ProverFailed(r1cs r1cs.R1CS, _solution interface{}) {
	// setup
	pk := DummySetup(r1cs)
	solution := assert.parseSolution(_solution)

	_, err := Prove(r1cs, pk, solution)
	assert.Error(err, "proving with bad solution should output an error")
}

// ProverSucceeded check that a solution solves a circuit
// for each expectedValues, this helper compares the output from backend.Inspect() after Solving.
// this helper also ensure the result vectors a*b=c
// it ensures running groth16.Prove and groth16.Verify returns true
// provided _solution must either implements frontend.Circuit or be
// a map[string]interface{}
func (assert *Assert) ProverSucceeded(r1cs r1cs.R1CS, _solution interface{}) {
	solution := assert.parseSolution(_solution)

	// setup
	pk, vk := Setup(r1cs)

	// ensure random sampling; calling setup twice should produce != pk and vk
	{
		// setup
		pk2, vk2 := Setup(r1cs)

		assert.True(pk2.IsDifferent(pk), "groth16 setup with same input should produce different outputs ")
		assert.True(vk2.IsDifferent(vk), "groth16 setup with same input should produce different outputs ")
	}

	// ensure expected Values are computed correctly
	assert.SolvingSucceeded(r1cs, solution)

	// prover
	proof, err := Prove(r1cs, pk, solution)
	assert.NoError(err, "proving with good solution should not output an error")

	// ensure random sampling; calling prove twice with same input should produce different proof
	{
		proof2, err := Prove(r1cs, pk, solution)
		assert.NoError(err, "proving with good solution should not output an error")
		assert.False(reflect.DeepEqual(proof, proof2), "calling prove twice with same input should produce different proof")
	}

	// verifier
	{
		err := Verify(proof, vk, solution)
		assert.NoError(err, "verifying proof with good solution should not output an error")
	}
}

// SolvingSucceeded Verifies that the R1CS is solved with the given solution, without executing groth16 workflow
func (assert *Assert) SolvingSucceeded(r1cs r1cs.R1CS, _solution interface{}) {
	solution := assert.parseSolution(_solution)
	assert.NoError(r1cs.IsSolved(solution))
}

// SolvingFailed Verifies that the R1CS is not solved with the given solution, without executing groth16 workflow
func (assert *Assert) SolvingFailed(r1cs r1cs.R1CS, _solution interface{}) {
	solution := assert.parseSolution(_solution)
	assert.Error(r1cs.IsSolved(solution))
}

func (assert *Assert) parseSolution(_solution interface{}) map[string]interface{} {
	solution, err := frontend.ParseWitness(_solution)
	assert.NoError(err)
	return solution
}
