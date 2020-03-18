package main

import (
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
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
		expectedValues := make(map[string]interface{})
		expectedValues["x^3"] = 27
		expectedValues["x"] = 3
		assert.Solved(r1cs, good, expectedValues)
	}

}
