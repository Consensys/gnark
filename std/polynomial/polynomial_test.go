package polynomial

import (
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type evalPolyCircuit struct {
	P          []frontend.Variable `gnark:",public"`
	At         frontend.Variable   `gnark:",secret"`
	Evaluation frontend.Variable   `gnark:",secret"`
}

func (c *evalPolyCircuit) Define(api frontend.API) error {
	p := Polynomial(c.P)
	evaluation := p.Eval(api, c.At)
	api.AssertIsEqual(evaluation, c.Evaluation)
	return nil
}

func testEvalPoly(t *testing.T, p []int64, at int64, evaluation int64) {
	assert := test.NewAssert(t)

	witness := evalPolyCircuit{
		P:          Polynomial(int64SliceToVariableSlice(p)),
		At:         at,
		Evaluation: evaluation,
	}

	assert.CheckCircuit(&evalPolyCircuit{P: make(Polynomial, len(p))}, test.WithValidAssignment(&witness))
}

func TestEvalPoly(t *testing.T) {
	testEvalPoly(t, []int64{1, 2, 3, 4}, 5, 586)
}

type evalDeltasCircuit struct {
	ExpectedDeltas []frontend.Variable
	At             frontend.Variable
}

func (c *evalDeltasCircuit) Define(api frontend.API) error {
	observedDeltas := computeDeltaAtNaive(api, c.At, len(c.ExpectedDeltas))
	for i := range c.ExpectedDeltas {
		api.AssertIsEqual(observedDeltas[i], c.ExpectedDeltas[i])
	}
	return nil
}

func testEvalDeltas(t *testing.T, at int64, expected []int64) {

	test.NewAssert(t).CheckCircuit(
		&evalDeltasCircuit{ExpectedDeltas: make([]frontend.Variable, len(expected))},

		test.WithValidAssignment(&evalDeltasCircuit{ExpectedDeltas: int64SliceToVariableSlice(expected), At: at}),
	)
}

func TestEvalDeltasLinear(t *testing.T) {
	testEvalDeltas(t, 2, []int64{-1, 2})
}

func TestEvalDeltasQuadratic(t *testing.T) {
	testEvalDeltas(t, 3, []int64{1, -3, 3})
}

type foldMultiLinCircuit struct {
	M      []frontend.Variable
	At     frontend.Variable
	Result []frontend.Variable
}

func (c *foldMultiLinCircuit) Define(api frontend.API) error {
	if len(c.M) != 2*len(c.Result) {
		return errors.New("folding size mismatch")
	}
	m := MultiLin(c.M)
	m.fold(api, c.At)
	for i := range c.Result {
		api.AssertIsEqual(m[i], c.Result[i])
	}
	return nil
}

func TestFoldSmall(t *testing.T) {
	test.NewAssert(t).CheckCircuit(
		&foldMultiLinCircuit{M: make([]frontend.Variable, 4), Result: make([]frontend.Variable, 2)},

		test.WithValidAssignment(&foldMultiLinCircuit{M: []frontend.Variable{0, 1, 2, 3}, At: 2, Result: []frontend.Variable{4, 5}}),
	)
}

type evalMultiLinCircuit struct {
	M          []frontend.Variable `gnark:",public"`
	At         []frontend.Variable `gnark:",secret"`
	Evaluation frontend.Variable   `gnark:",secret"`
}

func (c *evalMultiLinCircuit) Define(api frontend.API) error {
	m := MultiLin(c.M)
	evaluation := m.Evaluate(api, c.At)
	api.AssertIsEqual(evaluation, c.Evaluation)
	return nil
}

func TestEvalMultiLin(t *testing.T) {
	assert := test.NewAssert(t)

	// M = 2 X₀ + X₁ + 1
	witness := evalMultiLinCircuit{
		M:          MultiLin{1, 2, 3, 4},
		At:         []frontend.Variable{5, 6},
		Evaluation: 17,
	}

	assert.CheckCircuit(&evalMultiLinCircuit{M: make(MultiLin, 4), At: make([]frontend.Variable, 2)}, test.WithValidAssignment(&witness))
}

type evalEqCircuit struct {
	X  []frontend.Variable `gnark:",public"`
	Y  []frontend.Variable `gnark:",secret"`
	Eq frontend.Variable   `gnark:"secret"`
}

func (c *evalEqCircuit) Define(api frontend.API) error {
	evaluation := EvalEq(api, c.X, c.Y)
	api.AssertIsEqual(evaluation, c.Eq)
	return nil
}

func TestEvalEq(t *testing.T) {
	assert := test.NewAssert(t)

	witness := evalEqCircuit{
		X:  []frontend.Variable{1, 2, 3, 4},
		Y:  []frontend.Variable{5, 6, 7, 8},
		Eq: 148665,
	}

	assert.CheckCircuit(&evalEqCircuit{X: make([]frontend.Variable, 4), Y: make([]frontend.Variable, 4)}, test.WithValidAssignment(&witness))
}

type interpolateLDECircuit struct {
	At                    frontend.Variable   `gnark:",secret"`
	Values                []frontend.Variable `gnark:",public"`
	ExpectedInterpolation frontend.Variable   `gnark:",secret"`
}

func (c *interpolateLDECircuit) Define(api frontend.API) error {
	evaluation := InterpolateLDE(api, c.At, c.Values)
	api.AssertIsEqual(evaluation, c.ExpectedInterpolation)
	return nil
}

func testInterpolateLDE(t *testing.T, at int64, values []int64, expectedInterpolation int64) {

	test.NewAssert(t).CheckCircuit(
		&interpolateLDECircuit{Values: make([]frontend.Variable, len(values))},

		test.WithValidAssignment(&interpolateLDECircuit{At: at, Values: int64SliceToVariableSlice(values), ExpectedInterpolation: expectedInterpolation}),
	)
}

func TestInterpolateLDEOnRange(t *testing.T) {
	// The polynomial is 2 X⁴ - X³ - 9 X² + 9 X - 6
	testInterpolateLDE(
		t,
		5,
		[]int64{-6, -5, 0, 75, 334},
		939,
	)
}

func TestInterpolateLDEOnRangeWithinRange(t *testing.T) {
	// The polynomial is 2 X⁴ - X³ - 9 X² + 9 X - 6
	testInterpolateLDE(
		t,
		1,
		[]int64{-6, -5, 0, 75, 334},
		-5,
	)
}

func TestInterpolateLinearExtension(t *testing.T) {
	// The polynomial is 4X + 3
	testInterpolateLDE(
		t,
		2,
		[]int64{3, 7},
		11,
	)
}

func TestInterpolateQuadraticExtension(t *testing.T) {
	// The polynomial is 1 + 2X + 3X²
	testInterpolateLDE(
		t,
		3,
		[]int64{1, 6, 17},
		34,
	)

	testInterpolateLDE(
		t,
		-1,
		[]int64{1, 6, 17},
		2,
	)
}

func TestNegFactorial(t *testing.T) {
	for n, expected := range []int{0, -1, 2, -6, 24} {

		if observed := negFactorial(n); observed != expected {
			t.Error("negFactorial at", n, "gave", observed, "rather than", expected)
		}
	}
}

func int64SliceToVariableSlice(slice []int64) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(slice))
	for _, v := range slice {
		res = append(res, v)
	}
	return res
}

func ExampleMultiLin_Evaluate() {
	const logSize = 20
	const size = 1 << logSize
	m := MultiLin(make([]frontend.Variable, size))
	e := MultiLin(make([]frontend.Variable, logSize))

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &evalMultiLinCircuit{M: m, At: e, Evaluation: 0})
	if err != nil {
		panic(err)
	}
	fmt.Println("r1cs size:", cs.GetNbConstraints())

	cs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &evalMultiLinCircuit{M: m, At: e, Evaluation: 0})
	if err != nil {
		panic(err)
	}
	fmt.Println("scs size:", cs.GetNbConstraints())

	// Output: r1cs size: 1048627
	//scs size: 2097226
}
