package main

import (
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
)

func TestExponentiate(t *testing.T) {
	assert := groth16.NewAssert(t)
	r1cs := New() // y == x**e

	// TODO bigger numbers
	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "x", 2)
		bad.Assign(backend.Secret, "e", 12)
		bad.Assign(backend.Public, "y", 4095) // y != x**e
		assert.NotSolved(r1cs, bad)
	}

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "x", 2)
		bad.Assign(backend.Public, "e", 12) // e should be Secret
		bad.Assign(backend.Public, "y", 4096)
		assert.NotSolved(r1cs, bad)
	}

	{
		good := backend.NewAssignment()
		good.Assign(backend.Public, "x", 2)
		good.Assign(backend.Secret, "e", 12)
		good.Assign(backend.Public, "y", 4096)
		expectedValues := make(map[string]interface{})
		expectedValues["e[0]"] = 0
		expectedValues["e[1]"] = 0
		expectedValues["e[2]"] = 1
		expectedValues["e[3]"] = 1
		expectedValues["e[4]"] = 0
		expectedValues["e[5]"] = 0
		expectedValues["e[6]"] = 0
		expectedValues["e[7]"] = 0
		assert.Solved(r1cs, good, expectedValues)
	}

}
