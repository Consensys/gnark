package main

import (
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/bn256/groth16"
	"github.com/consensys/gurvy/bn256/fr"
)

func TestCubicEquation(t *testing.T) {
	assert := groth16.NewAssert(t)
	r1cs := New() // x**3+x+5 == y

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Secret, "x", 42)
		bad.Assign(backend.Public, "y", 42)
		assert.NotSolved(r1cs, bad)
	}

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "x", 3) // x should be Secret
		bad.Assign(backend.Public, "y", 35)
		assert.NotSolved(r1cs, bad)
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
		assert.Solved(r1cs, good, expectedValues)
	}

}
