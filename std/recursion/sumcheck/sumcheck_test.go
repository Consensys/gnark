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

type mulGate1 struct{}

func (m mulGate1) NbInputs() int { return 2 }
func (m mulGate1) Degree() int   { return 2 }
func (m mulGate1) Evaluate(api *bigIntEngine, dst *big.Int, vars ...*big.Int) *big.Int {
	if len(vars) != m.NbInputs() {
		panic("incorrect nb of inputs")
	}
	api.Mul(dst, vars[0], vars[1])
	return dst
}

func testMulGate1SumcheckInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, inputs [][]int) {
	var fr FR
	assert := test.NewAssert(t)
	inputB := make([][]*big.Int, len(inputs))
	for i := range inputB {
		inputB[i] = make([]*big.Int, mulGate1{}.NbInputs())
		for j := range inputs[i] {
			inputB[i][j] = big.NewInt(int64(inputs[i][j]))
		}
	}
	claim, evals, err := NewNativeGate(fr.Modulus(), mulGate1{}, inputB)
	assert.NoError(err)
	for i := range evals {
		t.Log(evals[i].String())
	}
	proof, err := Prove(current, fr.Modulus(), claim)
	assert.NoError(err)
	_ = proof
}

func TestMulGate1Sumcheck(t *testing.T) {
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{4, 3}, {2, 3}})
}
