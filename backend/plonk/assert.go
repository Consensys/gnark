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

package plonk

import (
	"testing"

	backend_bls377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	backend_bls381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn254/cs"
	backend_bw761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"

	"github.com/consensys/gnark/frontend"
	witness_bls377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bn256 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
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

func (assert *Assert) ProverSucceeded(sparseR1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {

	// checks if the system is solvable
	assert.SolvingSucceeded(sparseR1cs, witness)

	// generates public data
	publicData, err := SetupDummyCommitment(sparseR1cs, witness)
	assert.NoError(err, "Generating public data should not have failed")

	// generates the proof
	proof, err := Prove(sparseR1cs, publicData, witness)
	assert.NoError(err, "Proving with good witness should not output an error")

	// verifies the proof
	err = Verify(proof, publicData, witness)
	assert.NoError(err, "Verifying correct proof with correct witness should not output an error")

}

func (assert *Assert) ProverFailed(sparseR1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {

	// generates public data
	publicData, err := SetupDummyCommitment(sparseR1cs, witness)
	assert.NoError(err, "Generating public data should not have failed")

	// generates the proof
	proof, err := Prove(sparseR1cs, publicData, witness)

	// verifies the proof
	err = Verify(proof, publicData, witness)
	assert.Error(err, "Veryfing wrong proof should output an error")

}

// SolvingSucceeded Verifies that the sparse constraint system is solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingSucceeded(sparseR1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	assert.NoError(IsSolved(sparseR1cs, witness))
}

// SolvingFailed Verifies that the cs.PCS is not solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingFailed(sparseR1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	assert.Error(IsSolved(sparseR1cs, witness))
}

// IsSolved attempts to solve the constraint system with provided witness
// returns nil if it succeeds, error otherwise.
func IsSolved(sparseR1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) error {
	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn256.SparseR1CS:
		w := witness_bn256.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _sparseR1cs.IsSolved(w)
	case *backend_bls381.SparseR1CS:
		w := witness_bls381.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _sparseR1cs.IsSolved(w)
	case *backend_bls377.SparseR1CS:
		w := witness_bls377.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _sparseR1cs.IsSolved(w)
	case *backend_bw761.SparseR1CS:
		w := witness_bw761.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _sparseR1cs.IsSolved(w)
	default:
		panic("WIP")
	}
}
