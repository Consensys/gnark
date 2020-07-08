package main

import (
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/bn256/groth16"
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
	r1csBN256 := backend_bn256.Cast(r1cs) // specifies the circuit to bn256

	{
		err := frontend.MakeAssignable(&cubicCircuit)
		assert.NoError(err)

		cubicCircuit.X.Assign(42)
		cubicCircuit.Y.Assign(42)

		bad, err := frontend.ToAssignment(&cubicCircuit)
		assert.NoError(err)
		assert.NotSolved(&r1csBN256, bad)
	}

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Secret, "x", 42)
		bad.Assign(backend.Public, "y", 42)
		assert.NotSolved(&r1csBN256, bad)
	}

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "x", 3) // x should be Secret
		bad.Assign(backend.Public, "y", 35)
		assert.NotSolved(&r1csBN256, bad)
	}

	{
		good := backend.NewAssignment()
		good.Assign(backend.Secret, "x", 3)
		good.Assign(backend.Public, "y", 35)
		expectedValues := make(map[string]fr.Element)
		var x, xcube fr.Element
		xcube.SetUint64(27)
		expectedValues["x^3"] = xcube
		x.SetUint64(3)
		expectedValues["x"] = x
		assert.Solved(&r1csBN256, good, expectedValues)
	}

}
