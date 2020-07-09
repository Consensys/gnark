package main

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

func TestCubicEquation(t *testing.T) {

	assert := groth16.NewAssert(t)

	var cubicCircuit CubicCircuit

	// init context
	ctx := frontend.NewContext(gurvy.BN256)

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ctx, &cubicCircuit)
	assert.NoError(err)

	// TODO use ctx to "cast" into the good backend choice
	r1csBN256 := r1cs

	{
		err := frontend.MakeAssignable(&cubicCircuit)
		assert.NoError(err)

		cubicCircuit.X.Assign(42)
		cubicCircuit.Y.Assign(42)

		bad, err := frontend.ToAssignment(&cubicCircuit)
		assert.NoError(err)
		assert.NotSolved(r1csBN256, bad)
	}

	{
		bad := make(map[string]interface{})
		bad["x"] = 42
		bad["y"] = 42
		assert.NotSolved(r1csBN256, bad)
	}

	{
		good := make(map[string]interface{})
		good["x"] = 3
		good["y"] = 35
		expectedValues := make(map[string]interface{})
		var x, xcube fr.Element
		xcube.SetUint64(27)
		expectedValues["x^3"] = xcube
		x.SetUint64(3)
		expectedValues["x"] = x
		assert.Solved(r1csBN256, good, expectedValues)
	}

}
