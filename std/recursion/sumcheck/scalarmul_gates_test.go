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

type projAddGate[AE ArithEngine[E], E Element] struct {
	folding E
}

func (m projAddGate[AE, E]) NbInputs() int { return 6 }
func (m projAddGate[AE, E]) Degree() int   { return 4 }
func (m projAddGate[AE, E]) Evaluate(api AE, vars ...E) E {
	if len(vars) != m.NbInputs() {
		panic("incorrect nb of inputs")
	}
	X1, Y1, Z1 := vars[0], vars[1], vars[2]
	X2, Y2, Z2 := vars[3], vars[4], vars[5]
	b3 := api.Const(big.NewInt(21))
	t0 := api.Mul(X1, X2)
	t1 := api.Mul(Y1, Y2)
	t2 := api.Mul(Z1, Z2)
	t3 := api.Add(X1, Y1)
	t4 := api.Add(X2, Y2)
	t3 = api.Mul(t3, t4)
	t4 = api.Add(t0, t1)
	t3 = api.Sub(t3, t4)
	t4 = api.Add(Y1, Z1)
	X3 := api.Add(Y2, Z2)
	t4 = api.Mul(t4, X3)
	X3 = api.Add(t1, t2)
	t4 = api.Sub(t4, X3)
	X3 = api.Add(X1, Z1)
	Y3 := api.Add(X2, Z2)
	X3 = api.Mul(X3, Y3)
	Y3 = api.Add(t0, t2)
	Y3 = api.Sub(X3, Y3)
	X3 = api.Add(t0, t0)
	t0 = api.Add(X3, t0)
	t2 = api.Mul(b3, t2)
	Z3 := api.Add(t1, t2)
	t1 = api.Sub(t1, t2)
	Y3 = api.Mul(b3, Y3)
	X3 = api.Mul(t4, Y3)
	t2 = api.Mul(t3, t1)
	X3 = api.Sub(t2, X3)
	Y3 = api.Mul(Y3, t0)
	t1 = api.Mul(t1, Z3)
	Y3 = api.Add(t1, Y3)
	t0 = api.Mul(t0, t3)
	Z3 = api.Mul(Z3, t4)
	Z3 = api.Add(Z3, t0)

	res := api.Mul(m.folding, Z3)
	res = api.Add(res, Y3)
	res = api.Mul(m.folding, res)
	res = api.Add(res, X3)
	return res
}

type ProjAddSumcheckCircuit[FR emulated.FieldParams] struct {
	Inputs [][]emulated.Element[FR]

	Proof Proof[FR]

	// This is for generic case where nbClaims may be bigger than 1. But for
	// single claim checking the sizes of slices is 1. Additionally, in practice
	// we would compute claimed values in-circuit from the off-circuit gate
	// evaluations and evaluation points using commitment API.
	EvaluationPoints [][]emulated.Element[FR]
	Claimed          []emulated.Element[FR]
}

func (c *ProjAddSumcheckCircuit[FR]) Define(api frontend.API) error {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
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
	claim, err := NewGate[FR](api, projAddGate[*emuEngine[FR], *emulated.Element[FR]]{f.NewElement(123)}, inputs, evalPoints, claimedEvals)
	if err != nil {
		return fmt.Errorf("new gate claim: %w", err)
	}
	if err = v.Verify(claim, c.Proof); err != nil {
		return fmt.Errorf("verify sumcheck: %w", err)
	}
	return nil
}

func testProjAddSumCheckInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, inputs [][]int) {
	var fr FR
	nativeGate := projAddGate[*bigIntEngine, *big.Int]{folding: big.NewInt(123)}
	assert := test.NewAssert(t)
	inputB := make([][]*big.Int, len(inputs))
	for i := range inputB {
		inputB[i] = make([]*big.Int, len(inputs[i]))
		for j := range inputs[i] {
			inputB[i][j] = big.NewInt(int64(inputs[i][j]))
		}
	}
	evalPointsB, evalPointsPH, evalPointsC := getChallengeEvaluationPoints[FR](inputB)
	claim, evals, err := NewNativeGate(fr.Modulus(), nativeGate, inputB, evalPointsB)
	assert.NoError(err)
	proof, err := Prove(current, fr.Modulus(), claim)
	assert.NoError(err)
	nbVars := bits.Len(uint(len(inputs[0]))) - 1
	circuit := &ProjAddSumcheckCircuit[FR]{
		Inputs:           make([][]emulated.Element[FR], len(inputs)),
		Proof:            PlaceholderGateProof[FR](nbVars, nativeGate.Degree()),
		EvaluationPoints: evalPointsPH,
		Claimed:          make([]emulated.Element[FR], 1),
	}
	assignment := &ProjAddSumcheckCircuit[FR]{
		Inputs:           make([][]emulated.Element[FR], len(inputs)),
		Proof:            ValueOfProof[FR](proof),
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
}

func TestProjAddSumCheckSumcheck(t *testing.T) {
	// testProjAddSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{4, 3}, {2, 3}, {3, 6}, {4, 9}, {13, 3}, {31, 9}})
	// testProjAddSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4}, {5, 6, 7, 8}})
	// testProjAddSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4, 5, 6, 7, 8}, {11, 12, 13, 14, 15, 16, 17, 18}})
	inputs := [][]int{{1}, {2}, {3}, {4}, {5}, {6}}
	for i := 1; i < (1 << 10); i++ {
		inputs[0] = append(inputs[0], (inputs[0][i-1]+1)*2)
		inputs[1] = append(inputs[1], (inputs[1][i-1]+2)*7)
		inputs[2] = append(inputs[2], (inputs[2][i-1]+3)*6)
		inputs[3] = append(inputs[3], (inputs[3][i-1]+4)*5)
		inputs[4] = append(inputs[4], (inputs[4][i-1]+5)*4)
		inputs[5] = append(inputs[5], (inputs[5][i-1]+6)*3)
	}
	testProjAddSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), inputs)
}
