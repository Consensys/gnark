package polynomial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type thisShouldWork struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",secret"`
}

func (c *thisShouldWork) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.Y)
	return nil
}

func TestShouldWork(t *testing.T) {
	assert := test.NewAssert(t)

	witness := thisShouldWork{
		X: 4,
		Y: 4,
	}

	assert.SolvingSucceeded(&thisShouldWork{}, &witness, test.WithCurves(ecc.BN254))
}

type evalPolyCircuit struct {
	p          Polynomial        `gnark:",public"`
	at         frontend.Variable `gnark:",secret"`
	evaluation frontend.Variable `gnark:",secret"`
}

func (c *evalPolyCircuit) Define(api frontend.API) error {
	evaluation := c.p.Eval(api, c.at)
	api.AssertIsEqual(evaluation, c.evaluation)
	return nil
}

func TestEvalPoly(t *testing.T) {
	assert := test.NewAssert(t)

	witness := evalPolyCircuit{
		p:          Polynomial{1, 2, 3, 4},
		at:         5,
		evaluation: 586,
	}

	assert.SolvingSucceeded(&evalPolyCircuit{}, &witness, test.WithCurves(ecc.BN254))
}

type evalMultiLinCircuit struct {
	m          MultiLin            `gnark:",public"`
	at         []frontend.Variable `gnark:",secret"`
	evaluation frontend.Variable   `gnark:",secret"`
}

func (c *evalMultiLinCircuit) Define(api frontend.API) error {
	evaluation := c.m.Eval(api, c.at)
	api.AssertIsEqual(evaluation, c.evaluation)
	return nil
}

func TestEvalMultiLin(t *testing.T) {
	assert := test.NewAssert(t)

	witness := evalMultiLinCircuit{
		m:          MultiLin{1, 2, 3, 4},
		at:         []frontend.Variable{5, 6},
		evaluation: 17,
	}

	assert.SolvingSucceeded(&evalMultiLinCircuit{}, &witness, test.WithCurves(ecc.BN254))
}

type evalEqCircuit struct {
	x  []frontend.Variable `gnark:",public"`
	y  []frontend.Variable `gnark:",secret"`
	eq frontend.Variable   `gnark:"secret"`
}

func (c *evalEqCircuit) Define(api frontend.API) error {
	evaluation := EvalEq(api, c.x, c.y)
	api.AssertIsEqual(evaluation, c.eq)
	return nil
}

func TestEvalEq(t *testing.T) {
	assert := test.NewAssert(t)

	witness := evalEqCircuit{
		x:  []frontend.Variable{1, 2, 3, 4},
		y:  []frontend.Variable{5, 6, 7, 8},
		eq: 148665,
	}

	assert.SolvingSucceeded(&evalEqCircuit{}, &witness, test.WithCurves(ecc.BN254))
}
