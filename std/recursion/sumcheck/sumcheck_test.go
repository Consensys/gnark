package sumcheck

import (
	"fmt"
	"math/big"
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/test"
)

type MultilinearSumcheckCircuit[FR emulated.FieldParams] struct {
	Function polynomial.Multilinear[FR]
	Claim    emulated.Element[FR]

	Proof Proof[FR]
}

func (c *MultilinearSumcheckCircuit[FR]) Define(api frontend.API) error {
	v, err := NewVerifier[FR](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	claim, err := NewMultilinearClaim[FR](api, c.Function, &c.Claim)
	if err != nil {
		return fmt.Errorf("new ml claim: %w", err)
	}
	if err = v.Verify(claim, c.Proof); err != nil {
		return fmt.Errorf("verify sumcheck: %w", err)
	}
	return nil
}

func testMultilinearSumcheckInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, mle []int) {
	var fr FR
	assert := test.NewAssert(t)
	mleB := make([]*big.Int, len(mle))
	for i := range mle {
		mleB[i] = big.NewInt(int64(mle[i]))
	}

	claim, value, err := NewNativeMultilinearClaim(fr.Modulus(), mleB)
	assert.NoError(err)
	proof, err := Prove(current, fr.Modulus(), claim)
	assert.NoError(err)
	nbVars := bits.Len(uint(len(mle))) - 1
	circuit := &MultilinearSumcheckCircuit[FR]{
		Function: polynomial.PlaceholderMultilinear[FR](nbVars),
		Proof:    PlaceholderMultilinearProof[FR](nbVars),
	}
	assignment := &MultilinearSumcheckCircuit[FR]{
		Function: polynomial.ValueOfMultilinear[FR](mleB),
		Claim:    emulated.ValueOf[FR](value),
		Proof:    ValueOfProof[FR](proof),
	}
	err = test.IsSolved(circuit, assignment, current)
	assert.NoError(err)
}

func TestMultilinearSumcheck(t *testing.T) {
	testMultilinearSumcheckInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), []int{1, 2})
	testMultilinearSumcheckInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), []int{1, 2, 3, 4})
	testMultilinearSumcheckInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), []int{1, 2, 3, 4, 5, 6, 7, 8})
}
