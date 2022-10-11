package polynomial

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/nume-crypto/gnark-crypto/ecc"
	"testing"
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

func TestEvalPoly(t *testing.T) {
	assert := test.NewAssert(t)

	witness := evalPolyCircuit{
		P:          Polynomial{1, 2, 3, 4},
		At:         5,
		Evaluation: 586,
	}

	assert.SolvingSucceeded(&evalPolyCircuit{P: make(Polynomial, 4)}, &witness, test.WithCurves(ecc.BN254))
}

type evalMultiLinCircuit struct {
	M          []frontend.Variable `gnark:",public"`
	At         []frontend.Variable `gnark:",secret"`
	Evaluation frontend.Variable   `gnark:",secret"`
}

func (c *evalMultiLinCircuit) Define(api frontend.API) error {
	m := MultiLin(c.M)
	evaluation := m.Eval(api, c.At)
	api.AssertIsEqual(evaluation, c.Evaluation)
	return nil
}

func TestEvalMultiLin(t *testing.T) {
	assert := test.NewAssert(t)

	// M = 2 X_0 + X_1 + 1
	witness := evalMultiLinCircuit{
		M:          MultiLin{1, 2, 3, 4},
		At:         []frontend.Variable{5, 6},
		Evaluation: 17,
	}

	assert.SolvingSucceeded(&evalMultiLinCircuit{M: make(MultiLin, 4), At: make([]frontend.Variable, 2)}, &witness, test.WithCurves(ecc.BN254))
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

	assert.SolvingSucceeded(&evalEqCircuit{X: make([]frontend.Variable, 4), Y: make([]frontend.Variable, 4)}, &witness, test.WithCurves(ecc.BN254))
}

type interpolateLDEOnRangeCircuit struct {
	At                frontend.Variable   `gnark:",secret"`
	Values            []frontend.Variable `gnark:",public"`
	InterpolatedValue frontend.Variable   `gnark:",secret"`
}

func (c *interpolateLDEOnRangeCircuit) Define(api frontend.API) error {
	evaluation := InterpolateLDEOnRange(api, c.At, c.Values)
	api.AssertIsEqual(evaluation, c.InterpolatedValue)
	return nil
}

func TestInterpolateLDEOnRange(t *testing.T) {
	assert := test.NewAssert(t)

	// The polynomial is 2 X^4 - X^3 - 9 X^2 + 9 X - 6
	witness := interpolateLDEOnRangeCircuit{
		At:                5,
		Values:            []frontend.Variable{-6, -5, 0, 75, 334},
		InterpolatedValue: 939,
	}

	assert.SolvingSucceeded(&interpolateLDEOnRangeCircuit{Values: make([]frontend.Variable, 5)}, &witness, test.WithCurves(ecc.BN254))
}

func TestInterpolateLDEOnRangeWithinRange(t *testing.T) {
	assert := test.NewAssert(t)

	// The polynomial is 2 X^4 - X^3 - 9 X^2 + 9 X - 6
	witness := interpolateLDEOnRangeCircuit{
		At:                1,
		Values:            []frontend.Variable{-6, -5, 0, 75, 334},
		InterpolatedValue: -5,
	}

	assert.SolvingSucceeded(&interpolateLDEOnRangeCircuit{Values: make([]frontend.Variable, 5)}, &witness)
}
