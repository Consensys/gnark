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
	claim, err := newMultilinearClaim[FR](api, c.Function, &c.Claim)
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

	claim, value, err := newNativeMultilinearClaim(fr.Modulus(), mleB)
	assert.NoError(err)
	proof, err := prove(current, fr.Modulus(), claim)
	assert.NoError(err)
	nbVars := bits.Len(uint(len(mle))) - 1
	circuit := &MultilinearSumcheckCircuit[FR]{
		Function: polynomial.PlaceholderMultilinear[FR](nbVars),
		Proof:    placeholderMultilinearProof[FR](nbVars),
	}
	assignment := &MultilinearSumcheckCircuit[FR]{
		Function: polynomial.ValueOfMultilinear[FR](mleB),
		Claim:    emulated.ValueOf[FR](value),
		Proof:    valueOfProof[FR](proof),
	}
	err = test.IsSolved(circuit, assignment, current)
	assert.NoError(err)
}

func TestMultilinearSumcheck(t *testing.T) {
	testMultilinearSumcheckInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), []int{1, 2})
	testMultilinearSumcheckInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), []int{1, 2, 3, 4})
	testMultilinearSumcheckInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), []int{1, 2, 3, 4, 5, 6, 7, 8})
}

func getChallengeEvaluationPoints[FR emulated.FieldParams](inputs [][]*big.Int) (bigints [][]*big.Int, placeholders [][]emulated.Element[FR], values [][]emulated.Element[FR]) {
	// this is for testing purposes. In practice we should obtain them randomly.
	// We can use commitment API given the inputs and the expected value
	// (computed out-circuit).
	nbClaims := 1
	nbInstances := len(inputs[0])
	nbVars := bits.Len(uint(nbInstances)) - 1

	bigints = make([][]*big.Int, nbClaims)
	placeholders = make([][]emulated.Element[FR], nbClaims)
	values = make([][]emulated.Element[FR], nbClaims)

	bigints[0] = make([]*big.Int, nbVars)
	placeholders[0] = make([]emulated.Element[FR], nbVars)
	values[0] = make([]emulated.Element[FR], nbVars)

	for i := 0; i < nbVars; i++ {
		bigints[0][i] = big.NewInt(int64(i + 123))
		values[0][i] = emulated.ValueOf[FR](bigints[0][i])
	}

	return
}

type mulGate1[AE arithEngine[E], E element] struct{}

func (m mulGate1[AE, E]) NbInputs() int { return 2 }
func (m mulGate1[AE, E]) Degree() int   { return 2 }
func (m mulGate1[AE, E]) Evaluate(api AE, vars ...E) E {
	if len(vars) != m.NbInputs() {
		panic("incorrect nb of inputs")
	}
	return api.Mul(vars[0], vars[1])
}

type MulGateSumcheck[FR emulated.FieldParams] struct {
	Inputs [][]emulated.Element[FR]

	Proof Proof[FR]

	// This is for generic case where nbClaims may be bigger than 1. But for
	// single claim checking the sizes of slices is 1. Additionally, in practice
	// we would compute claimed values in-circuit from the off-circuit gate
	// evaluations and evaluation points using commitment API.
	EvaluationPoints [][]emulated.Element[FR]
	Claimed          []emulated.Element[FR]
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
	claimedEvals := polynomial.FromSlice[FR](c.Claimed)
	evalPoints := make([][]*emulated.Element[FR], len(c.EvaluationPoints))
	for i := range c.EvaluationPoints {
		evalPoints[i] = polynomial.FromSlice[FR](c.EvaluationPoints[i])
	}
	claim, err := newGate[FR](api, mulGate1[*emuEngine[FR], *emulated.Element[FR]]{}, inputs, evalPoints, claimedEvals)
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
	var nativeGate mulGate1[*bigIntEngine, *big.Int]
	assert := test.NewAssert(t)
	inputB := make([][]*big.Int, len(inputs))
	for i := range inputB {
		inputB[i] = make([]*big.Int, len(inputs[i]))
		for j := range inputs[i] {
			inputB[i][j] = big.NewInt(int64(inputs[i][j]))
		}
	}
	evalPointsB, evalPointsPH, evalPointsC := getChallengeEvaluationPoints[FR](inputB)
	claim, evals, err := newNativeGate(fr.Modulus(), nativeGate, inputB, evalPointsB)
	assert.NoError(err)
	proof, err := prove(current, fr.Modulus(), claim)
	assert.NoError(err)
	nbVars := bits.Len(uint(len(inputs[0]))) - 1
	circuit := &MulGateSumcheck[FR]{
		Inputs:           make([][]emulated.Element[FR], len(inputs)),
		Proof:            placeholderGateProof[FR](nbVars, nativeGate.Degree()),
		EvaluationPoints: evalPointsPH,
		Claimed:          make([]emulated.Element[FR], 1),
	}
	assignment := &MulGateSumcheck[FR]{
		Inputs:           make([][]emulated.Element[FR], len(inputs)),
		Proof:            valueOfProof[FR](proof),
		EvaluationPoints: evalPointsC,
		Claimed:          []emulated.Element[FR]{emulated.ValueOf[FR](evals[0])},
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
	// frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
}

func TestMulGate1Sumcheck(t *testing.T) {
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{4, 3}, {2, 3}})
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4}, {5, 6, 7, 8}})
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4, 5, 6, 7, 8}, {11, 12, 13, 14, 15, 16, 17, 18}})
	inputs := [][]int{{1}, {2}}
	for i := 1; i < (1 << 10); i++ {
		inputs[0] = append(inputs[0], inputs[0][i-1]+1)
		inputs[1] = append(inputs[1], inputs[1][i-1]+2)
	}
	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), inputs)
}
