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
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/consensys/gnark/frontend"
	backend_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	backend_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	backend_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	backend_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
	gnarkio "github.com/consensys/gnark/io"
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

// ProverFailed check that a witness does NOT solve a circuit
func (assert *Assert) ProverFailed(r1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	// setup
	pk, err := DummySetup(r1cs)
	assert.NoError(err)
	_, err = Prove(r1cs, pk, witness)
	assert.Error(err, "proving with bad witness should output an error")
}

// ProverSucceeded check that a witness solves a circuit
//
// 1. Runs groth16.Setup()
//
// 2. Solves the R1CS
//
// 3. Runs groth16.Prove()
//
// 4. Runs groth16.Verify()
//
// 5. Ensure deserialization(serialization) of generated objects is correct
//
// ensure result vectors a*b=c, and check other properties like random sampling
func (assert *Assert) ProverSucceeded(r1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	// setup
	pk, vk, err := Setup(r1cs)
	assert.NoError(err)

	// ensure random sampling; calling setup twice should produce != pk and vk
	{
		// setup
		pk2, vk2, err := Setup(r1cs)
		assert.NoError(err)

		assert.True(pk2.IsDifferent(pk), "groth16 setup with same witness should produce different outputs ")
		assert.True(vk2.IsDifferent(vk), "groth16 setup with same witness should produce different outputs ")
	}

	// ensure expected Values are computed correctly
	assert.SolvingSucceeded(r1cs, witness)

	// extract full witness & public witness

	// prover
	proof, err := Prove(r1cs, pk, witness)
	assert.NoError(err, "proving with good witness should not output an error")

	// ensure random sampling; calling prove twice with same witness should produce different proof
	{
		proof2, err := Prove(r1cs, pk, witness)
		assert.NoError(err, "proving with good witness should not output an error")
		assert.False(reflect.DeepEqual(proof, proof2), "calling prove twice with same input should produce different proof")
	}

	// verifier
	{
		err := Verify(proof, vk, witness)
		assert.NoError(err, "verifying proof with good witness should not output an error")
	}

	// serialization
	assert.serializationSucceeded(proof, NewProof(r1cs.CurveID()))
	assert.serializationSucceeded(pk, NewProvingKey(r1cs.CurveID()))
	assert.serializationSucceeded(vk, NewVerifyingKey(r1cs.CurveID()))
	assert.serializationRawSucceeded(proof, NewProof(r1cs.CurveID()))
	assert.serializationRawSucceeded(pk, NewProvingKey(r1cs.CurveID()))
	assert.serializationRawSucceeded(vk, NewVerifyingKey(r1cs.CurveID()))
}

func (assert *Assert) serializationSucceeded(from io.WriterTo, to io.ReaderFrom) {
	var buf bytes.Buffer
	written, err := from.WriteTo(&buf)
	assert.NoError(err, "serializing to buffer failed")

	read, err := to.ReadFrom(&buf)
	assert.NoError(err, "desererializing from buffer failed")

	assert.EqualValues(written, read, "number of bytes read and written don't match")
}

func (assert *Assert) serializationRawSucceeded(from gnarkio.WriterRawTo, to io.ReaderFrom) {
	var buf bytes.Buffer
	written, err := from.WriteRawTo(&buf)
	assert.NoError(err, "serializing raw to buffer failed")

	read, err := to.ReadFrom(&buf)
	assert.NoError(err, "desererializing raw from buffer failed")

	assert.EqualValues(written, read, "number of bytes read and written don't match")
}

// SolvingSucceeded Verifies that the R1CS is solved with the given witness, without executing groth16 workflow
func (assert *Assert) SolvingSucceeded(r1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	assert.NoError(IsSolved(r1cs, witness))
}

// SolvingFailed Verifies that the R1CS is not solved with the given witness, without executing groth16 workflow
func (assert *Assert) SolvingFailed(r1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) {
	assert.Error(IsSolved(r1cs, witness))
}

// IsSolved attempts to solve the constraint system with provided witness
// returns nil if it succeeds, error otherwise.
func IsSolved(r1cs frontend.CompiledConstraintSystem, witness frontend.Circuit) error {
	switch _r1cs := r1cs.(type) {
	case *backend_bls12377.R1CS:
		w := witness_bls12377.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w)
	case *backend_bls12381.R1CS:
		w := witness_bls12381.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w)
	case *backend_bn254.R1CS:
		w := witness_bn254.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w)
	case *backend_bw6761.R1CS:
		w := witness_bw6761.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w)
	default:
		panic("unrecognized R1CS curve type")
	}
}
