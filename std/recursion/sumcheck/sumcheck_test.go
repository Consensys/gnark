package sumcheck

import (
	"fmt"
	"math/big"
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
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

type mulGate1[AE ArithEngine[E], E Element] struct{}

func (m mulGate1[AE, E]) NbInputs() int { return 2 }
func (m mulGate1[AE, E]) Degree() int   { return 2 }
func (m mulGate1[AE, E]) Evaluate(api AE, dst E, vars ...E) E {
	if len(vars) != m.NbInputs() {
		panic("incorrect nb of inputs")
	}
	return api.Mul(dst, vars[0], vars[1])
}

type MulGateSumcheck[FR emulated.FieldParams] struct {
	Claimed emulated.Element[FR]
	Inputs  [][]emulated.Element[FR]

	Proof Proof[FR]
}

func (c *MulGateSumcheck[FR]) Define(api frontend.API) error {
	v, err := NewVerifier[FR](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	inputs := make([][]*emulated.Element[FR], len(c.Inputs))
	for i := range inputs {
		inputs[i] = make([]*emulated.Element[FR], len(c.Inputs[i]))
		for j := range inputs[i] {
			inputs[i][j] = &c.Inputs[i][j]
		}
	}
	claimedEvals := []*emulated.Element[FR]{&c.Claimed}
	claim, err := NewGate[FR](api, mulGate1[*emuEngine[FR], *emulated.Element[FR]]{}, inputs, claimedEvals)
	if err != nil {
		return fmt.Errorf("new gate claim: %w", err)
	}
	if err = v.Verify(claim, c.Proof); err != nil {
		return fmt.Errorf("verify sumcheck: %w", err)
	}
	return nil
}

func testMulGate1SumcheckInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, inputs [][]int) {
	var fr FR
	t.Log("fr", fr.Modulus().String())
	assert := test.NewAssert(t)
	inputB := make([][]*big.Int, len(inputs))
	for i := range inputB {
		inputB[i] = make([]*big.Int, len(inputs[i]))
		for j := range inputs[i] {
			inputB[i][j] = big.NewInt(int64(inputs[i][j]))
		}
	}
	claim, evals, err := NewNativeGate(fr.Modulus(), mulGate1[*bigIntEngine, *big.Int]{}, inputB)
	assert.NoError(err)
	proof, err := Prove(current, fr.Modulus(), claim)
	assert.NoError(err)
	nbVars := bits.Len(uint(len(inputs[0]))) - 1
	circuit := &MulGateSumcheck[FR]{
		Proof:  PlaceholderGateProof[FR](nbVars, 2),
		Inputs: make([][]emulated.Element[FR], len(inputs)),
	}
	assignment := &MulGateSumcheck[FR]{
		Claimed: emulated.ValueOf[FR](evals[0]),
		Proof:   ValueOfProof[FR](proof),
		Inputs:  make([][]emulated.Element[FR], len(inputs)),
	}
	for i := range inputs {
		circuit.Inputs[i] = make([]emulated.Element[FR], len(inputs[i]))
		assignment.Inputs[i] = make([]emulated.Element[FR], len(inputs[i]))
		for j := range inputs[i] {
			assignment.Inputs[i][j] = emulated.ValueOf[FR](inputs[i][j])
		}
	}
	err = test.IsSolved(circuit, assignment, current)
	assert.NoError(err)
	frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
}

func TestMulGate1Sumcheck(t *testing.T) {
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{4, 3}, {2, 3}})
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4}, {5, 6, 7, 8}})
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4, 5, 6, 7, 8}, {11, 12, 13, 14, 15, 16, 17, 18}})
}
