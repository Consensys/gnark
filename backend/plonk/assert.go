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
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"

	cs_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	cs_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	cs_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	cs_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	cs_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"

	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
	"github.com/consensys/gnark-crypto/kzg"
)

// Assert is a helper to test circuits
type Assert struct {
	*require.Assertions
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

func (assert *Assert) ProverSucceeded(ccs frontend.CompiledConstraintSystem, witness frontend.Circuit, hintFunctions ...hint.Function) {

	// checks if the system is solvable
	assert.SolvingSucceeded(ccs, witness)

	// generates public data
	srs, err := newKZGSrs(ccs)
	assert.NoError(err, "building (test) kzg srs failed")
	pk, vk, err := Setup(ccs, srs)
	assert.NoError(err, "Generating public data should not have failed")

	// generates the proof
	proof, err := Prove(ccs, pk, witness, hintFunctions)
	assert.NoError(err, "Proving with good witness should not output an error")

	// verifies the proof
	err = Verify(proof, vk, witness)
	assert.NoError(err, "Verifying correct proof with correct witness should not output an error")

}

func (assert *Assert) ProverFailed(ccs frontend.CompiledConstraintSystem, witness frontend.Circuit, hintFunctions ...hint.Function) {

	// generates public data
	srs, err := newKZGSrs(ccs)
	assert.NoError(err, "building (test) kzg srs failed")
	pk, _, err := Setup(ccs, srs)
	assert.NoError(err, "Generating public data should not have failed")

	// generates the proof
	_, err = Prove(ccs, pk, witness, hintFunctions)
	assert.Error(err, "generating an incorrect proof should output an error")
}

// SolvingSucceeded Verifies that the sparse constraint system is solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingSucceeded(ccs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	assert.NoError(IsSolved(ccs, witness))
}

// SolvingFailed Verifies that the cs.PCS is not solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingFailed(ccs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	assert.Error(IsSolved(ccs, witness))
}

// IsSolved attempts to solve the constraint system with provided witness
// returns nil if it succeeds, error otherwise.
func IsSolved(ccs frontend.CompiledConstraintSystem, witness frontend.Circuit, hintFunctions ...hint.Function) error {
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		w := witness_bn254.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, hintFunctions)
	case *cs_bls12381.SparseR1CS:
		w := witness_bls12381.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, hintFunctions)
	case *cs_bls12377.SparseR1CS:
		w := witness_bls12377.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, hintFunctions)
	case *cs_bw6761.SparseR1CS:
		w := witness_bw6761.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, hintFunctions)
	case *cs_bls24315.SparseR1CS:
		w := witness_bls24315.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, hintFunctions)
	default:
		panic("unknown constraint system type")
	}
}

func newKZGSrs(ccs frontend.CompiledConstraintSystem) (kzg.SRS, error) {
	fakeRandomness := new(big.Int).SetInt64(42)

	// no randomness in the test SRS
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		size := uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
		return kzg_bn254.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bls12381.SparseR1CS:
		size := uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
		return kzg_bls12381.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bls12377.SparseR1CS:
		size := uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
		return kzg_bls12377.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bw6761.SparseR1CS:
		size := uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
		return kzg_bw6761.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bls24315.SparseR1CS:
		size := uint64(len(tccs.Constraints) + len(tccs.Assertions) + tccs.NbPublicVariables)
		return kzg_bls24315.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	default:
		panic("unknown constraint system type")
	}
}
