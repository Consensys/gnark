package math

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type LessThanCircuit struct {
	A              frontend.Variable `gnark:",public"`
	B              frontend.Variable `gnark:",public"`
	ExpectedOutput frontend.Variable `gnark:",public"`
}

func (c *LessThanCircuit) Define(api frontend.API) error {
	math, _ := NewMath(api)
	output := math.LessThan(c.A, c.B)

	api.AssertIsEqual(output, c.ExpectedOutput)

	return nil
}

func TestLessThan(t *testing.T) {
	assert := test.NewAssert(t)

	var lessThanCircuit LessThanCircuit

	assert.ProverSucceeded(&lessThanCircuit, &LessThanCircuit{
		A:              9,
		B:              10,
		ExpectedOutput: 1,
	})

	assert.ProverSucceeded(&lessThanCircuit, &LessThanCircuit{
		A:              10,
		B:              10,
		ExpectedOutput: 0,
	})

	assert.ProverSucceeded(&lessThanCircuit, &LessThanCircuit{
		A:              11,
		B:              10,
		ExpectedOutput: 0,
	})
}

type IsEqualCircuit struct {
	A              frontend.Variable `gnark:",public"`
	B              frontend.Variable `gnark:",public"`
	ExpectedOutput frontend.Variable `gnark:",public"`
}

func (c *IsEqualCircuit) Define(api frontend.API) error {
	math, _ := NewMath(api)
	output := math.IsEqual(c.A, c.B)

	api.AssertIsEqual(output, c.ExpectedOutput)

	return nil
}

func TestIsEqual(t *testing.T) {
	assert := test.NewAssert(t)

	var isEqualCircuit IsEqualCircuit

	assert.ProverSucceeded(&isEqualCircuit, &IsEqualCircuit{
		A:              10,
		B:              10,
		ExpectedOutput: 1,
	})

	assert.ProverSucceeded(&isEqualCircuit, &IsEqualCircuit{
		A:              9,
		B:              10,
		ExpectedOutput: 0,
	})
}
