package polynomial

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type evalPolyCircuit[FR emulated.FieldParams] struct {
	P          []emulated.Element[FR] `gnark:",public"`
	At         emulated.Element[FR]   `gnark:",secret"`
	Evaluation emulated.Element[FR]   `gnark:",secret"`
}

func (c *evalPolyCircuit[FR]) Define(api frontend.API) error {
	p, err := New[FR](api)
	if err != nil {
		return err
	}
	// P := polynomial.FromSlice(c.P)
	res := p.EvalUnivariate(c.P, &c.At)
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(res, &c.Evaluation)
	return nil
}

func testEvalPoly[FR emulated.FieldParams](t *testing.T, p []int64, at int64, evaluation int64) {
	assert := test.NewAssert(t)
	P := make([]emulated.Element[FR], len(p))
	for i := range P {
		P[i] = emulated.ValueOf[FR](p[i])
	}
	witness := evalPolyCircuit[FR]{
		P:          P,
		At:         emulated.ValueOf[FR](at),
		Evaluation: emulated.ValueOf[FR](evaluation),
	}

	assert.CheckCircuit(&evalPolyCircuit[FR]{P: make([]emulated.Element[FR], len(p))}, test.WithValidAssignment(&witness))
}

func TestEvalPoly(t *testing.T) {
	testEvalPoly[emparams.BN254Fr](t, []int64{1, 2, 3, 4}, 5, 586)
}

type evalMultiLinCircuit[FR emulated.FieldParams] struct {
	M          []emulated.Element[FR] `gnark:",public"`
	At         []emulated.Element[FR] `gnark:",secret"`
	Evaluation emulated.Element[FR]   `gnark:",secret"`
}

func (c *evalMultiLinCircuit[FR]) Define(api frontend.API) error {
	p, err := New[FR](api)
	if err != nil {
		return err
	}
	// M := polynomial.FromSlice(c.M)
	X := FromSlice(c.At)
	res, err := p.EvalMultilinear(X, c.M)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(res, &c.Evaluation)
	return nil
}

func TestEvalMultiLin(t *testing.T) {
	testEvalMultiLin[emparams.BN254Fr](t)
}

func testEvalMultiLin[FR emulated.FieldParams](t *testing.T) {
	assert := test.NewAssert(t)

	M := make([]emulated.Element[FR], 4)
	for i := range M {
		M[i] = emulated.ValueOf[FR](1 + i)
	}
	X := make([]emulated.Element[FR], 2)
	for i := range X {
		X[i] = emulated.ValueOf[FR](5 + i)
	}

	// M = 2 X₀ + X₁ + 1
	witness := evalMultiLinCircuit[FR]{
		M:          M,
		At:         X,
		Evaluation: emulated.ValueOf[FR](17),
	}

	assert.CheckCircuit(&evalMultiLinCircuit[FR]{M: make([]emulated.Element[FR], 4), At: make([]emulated.Element[FR], 2)}, test.WithValidAssignment(&witness))
}

type evalEqCircuit[FR emulated.FieldParams] struct {
	X  []emulated.Element[FR] `gnark:",public"`
	Y  []emulated.Element[FR] `gnark:",secret"`
	Eq emulated.Element[FR]   `gnark:"secret"`
}

func (c *evalEqCircuit[FR]) Define(api frontend.API) error {
	p, err := New[FR](api)
	if err != nil {
		return err
	}
	X := FromSlice(c.X)
	Y := FromSlice(c.Y)
	evaluation := p.EvalEqual(X, Y)
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(evaluation, &c.Eq)
	return nil
}

func TestEvalEq(t *testing.T) {
	testEvalEq[emparams.BN254Fr](t)
}

func testEvalEq[FR emulated.FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	x := []int{1, 2, 3, 4}
	y := []int{5, 6, 7, 8}
	X := make([]emulated.Element[FR], len(x))
	Y := make([]emulated.Element[FR], len(y))
	for i := range x {
		X[i] = emulated.ValueOf[FR](x[i])
		Y[i] = emulated.ValueOf[FR](y[i])
	}

	witness := evalEqCircuit[FR]{
		X:  X,
		Y:  Y,
		Eq: emulated.ValueOf[FR](148665),
	}

	assert.CheckCircuit(&evalEqCircuit[FR]{X: make([]emulated.Element[FR], 4), Y: make([]emulated.Element[FR], 4)}, test.WithValidAssignment(&witness))
}

type interpolateLDECircuit[FR emulated.FieldParams] struct {
	At       emulated.Element[FR]   `gnark:",secret"`
	Values   []emulated.Element[FR] `gnark:",public"`
	Expected emulated.Element[FR]   `gnark:",secret"`
}

func (c *interpolateLDECircuit[FR]) Define(api frontend.API) error {
	p, err := New[FR](api)
	if err != nil {
		return err
	}
	vals := FromSlice(c.Values)
	res := p.InterpolateLDE(&c.At, vals)
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func testInterpolateLDE[FR emulated.FieldParams](t *testing.T, at int64, values []int64, expected int64) {
	assert := test.NewAssert(t)
	P := make([]emulated.Element[FR], len(values))
	for i := range values {
		P[i] = emulated.ValueOf[FR](values[i])
	}
	assignment := &interpolateLDECircuit[FR]{
		At:       emulated.ValueOf[FR](at),
		Values:   P,
		Expected: emulated.ValueOf[FR](expected),
	}

	assert.CheckCircuit(&interpolateLDECircuit[FR]{Values: make([]emulated.Element[FR], len(values))}, test.WithValidAssignment(assignment))
}

func TestInterpolateLDEOnRange(t *testing.T) {
	// The polynomial is 2 X⁴ - X³ - 9 X² + 9 X - 6
	testInterpolateLDE[emparams.BN254Fr](t, 5, []int64{-6, -5, 0, 75, 334}, 939)
}

func TestInterpolateLDEOnRangeWithinRange(t *testing.T) {
	// The polynomial is 2 X⁴ - X³ - 9 X² + 9 X - 6
	testInterpolateLDE[emparams.BN254Fr](t, 1, []int64{-6, -5, 0, 75, 334}, -5)
}

func TestInterpolateLinearExtension(t *testing.T) {
	// The polynomial is 4X + 3
	testInterpolateLDE[emparams.BN254Fr](t, 2, []int64{3, 7}, 11)
}

func TestInterpolateQuadraticExtension(t *testing.T) {
	// The polynomial is 1 + 2X + 3X²
	testInterpolateLDE[emparams.BN254Fr](t, 3, []int64{1, 6, 17}, 34)
	testInterpolateLDE[emparams.BN254Fr](t, -1, []int64{1, 6, 17}, 2)
}

type TestPartialMultilinearEvalCircuit[FR emulated.FieldParams] struct {
	At []emulated.Element[FR] `gnark:",public"`
}

func (c *TestPartialMultilinearEvalCircuit[FR]) Define(api frontend.API) error {
	p, err := New[FR](api)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	At := FromSlice(c.At)
	coefs := p.partialMultilinearEval(At)
	res := f.Zero()
	for i := range coefs {
		res = f.Add(res, coefs[i])
	}
	ones := make([]emulated.Element[FR], 1<<len(c.At))
	for i := range ones {
		ones[i] = emulated.ValueOf[FR](1)
	}
	evaled, err := p.EvalMultilinear(At, ones)
	if err != nil {
		return err
	}
	f.AssertIsEqual(res, evaled)
	return nil
}

func TestPartialMultilinearEval(t *testing.T) {
	testPartialMultilinearEval[emparams.BN254Fr](t, []int64{2, 3, 4, 5})
}

func testPartialMultilinearEval[FR emulated.FieldParams](t *testing.T, at []int64) {
	assert := test.NewAssert(t)
	atAssignment := make([]emulated.Element[FR], len(at))
	for i := range at {
		atAssignment[i] = emulated.ValueOf[FR](at[i])
	}
	assignment := &TestPartialMultilinearEvalCircuit[FR]{
		At: atAssignment,
	}
	assert.CheckCircuit(&TestPartialMultilinearEvalCircuit[FR]{At: make([]emulated.Element[FR], len(atAssignment))}, test.WithValidAssignment(assignment))
}

type TestEvalMultilinear2Circuit[FR emulated.FieldParams] struct {
	M  []Multilinear[FR]      `gnark:",public"`
	At []emulated.Element[FR] `gnark:",secret"`
}

func (c *TestEvalMultilinear2Circuit[FR]) Define(api frontend.API) error {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return err
	}
	p, err := New[FR](api)
	if err != nil {
		return err
	}
	X := FromSlice(c.At)
	res2, err := p.EvalMultilinearMany(X, c.M...)
	if err != nil {
		return err
	}
	for i := range c.M {
		res, err := p.evalMultilinearOld(c.M[i], X)
		if err != nil {
			return err
		}
		f.AssertIsEqual(res2[i], res)
	}
	return nil
}

func TestEvalMultiLin2(t *testing.T) {
	testEvalMultiLin2[emparams.BN254Fr](t)
}

func testEvalMultiLin2[FR emulated.FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	nbML := 4
	nbVar := 3
	nbVals := 1 << nbVar

	M := make([]Multilinear[FR], nbML)
	for i := range M {
		M[i] = make([]emulated.Element[FR], nbVals)
		for j := range M[i] {
			M[i][j] = emulated.ValueOf[FR](1 + nbML*i + j)
		}
	}
	X := make([]emulated.Element[FR], 3)
	for i := range X {
		X[i] = emulated.ValueOf[FR](5 + i)
	}

	// M = 2 X₀ + X₁ + 1
	witness := TestEvalMultilinear2Circuit[FR]{
		M:  M,
		At: X,
	}
	circuit := &TestEvalMultilinear2Circuit[FR]{M: make([]Multilinear[FR], nbML), At: make([]emulated.Element[FR], nbVar)}
	for i := range circuit.M {
		circuit.M[i] = make([]emulated.Element[FR], nbVals)
	}
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness))
}
