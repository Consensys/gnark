package main

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

func TestCubicEquation(t *testing.T) {
	assert := groth16.NewAssert(t)

	var cubicCircuit CubicCircuit

	// init context
	ctx := frontend.NewContext(gurvy.BN256)

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ctx, &cubicCircuit)
	assert.NoError(err)

	{
		cubicCircuit.X.Assign(42)
		cubicCircuit.Y.Assign(42)

		assert.NotSolved(r1cs, &cubicCircuit)
	}

	{
		cubicCircuit.X.Assign(3)
		cubicCircuit.Y.Assign(35)
		expectedValues := make(map[string]interface{})
		expectedValues["x^3"] = 27
		expectedValues["x"] = 3
		assert.Solved(r1cs, &cubicCircuit, expectedValues)
	}

}
