// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

type scalarMulGLVAndFakeGLVTrivialDecompCircuit struct {
	A G1Affine
	S frontend.Variable
}

func (c *scalarMulGLVAndFakeGLVTrivialDecompCircuit) Define(api frontend.API) error {
	var got G1Affine
	got.scalarMulGLVAndFakeGLV(api, c.A, c.S)
	return nil
}

// zeroHalfGCDEisenstein replaces the honest halfGCDEisenstein hint with one
// that returns the all-zeros decomposition (u1 = u2 = v1 = v2 = q = 0). The
// signs are also zero (positive). This is the malicious-hint shape the
// soundness fix protects against.
func zeroHalfGCDEisenstein(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 10 {
		return errors.New("expecting ten outputs")
	}
	for i := range outputs {
		outputs[i].SetUint64(0)
	}
	return nil
}

// TestScalarMulGLVAndFakeGLV_TrivialDecompositionRegression: regression for a
// soundness issue in scalarMulGLVAndFakeGLV. A malicious halfGCDEisenstein
// hint returning the trivial all-zeros decomposition (u1=u2=v1=v2=q=0) makes
// the relation s·(v1 + λ·v2) + u1 + λ·u2 - r·q = 0 vacuous and lets the
// scalar-mul hint output be any point. The fix asserts NOT (v1=0 AND v2=0).
func TestScalarMulGLVAndFakeGLV_TrivialDecompositionRegression(t *testing.T) {
	assert := require.New(t)

	_, _, gAff, _ := bls12377.Generators()
	var s fr.Element
	s.SetUint64(7)

	witness := scalarMulGLVAndFakeGLVTrivialDecompCircuit{S: s.String()}
	witness.A.Assign(&gAff)

	// Honest path is satisfiable.
	err := test.IsSolved(
		&scalarMulGLVAndFakeGLVTrivialDecompCircuit{},
		&witness,
		ecc.BW6_761.ScalarField(),
	)
	assert.NoError(err)

	// Malicious all-zeros hint must be rejected.
	err = test.IsSolved(
		&scalarMulGLVAndFakeGLVTrivialDecompCircuit{},
		&witness,
		ecc.BW6_761.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(halfGCDEisenstein), zeroHalfGCDEisenstein),
	)
	assert.Error(err, "trivial all-zeros Eisenstein decomposition was accepted — soundness break")
}
