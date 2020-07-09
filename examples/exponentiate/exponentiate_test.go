package main

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gurvy"
)

func TestExponentiate(t *testing.T) {

	assert := groth16.NewAssert(t)

	r1cs := New() // y == x**e, captures the geometry of the circuit, not tied to any curve.

	r1csBN256 := r1cs.ToR1CS(gurvy.BN256)

	// TODO bigger numbers
	{
		bad := make(map[string]interface{})
		bad["x"] = 2
		bad["e"] = 12
		bad["y"] = 4095 // y != x**e
		assert.NotSolved(r1csBN256, bad)
	}

	{
		good := make(map[string]interface{})
		good["x"] = 2
		good["e"] = 12
		good["y"] = 4096
		expectedValues := make(map[string]interface{})
		expectedValues["e[0]"] = 0
		expectedValues["e[1]"] = 0
		expectedValues["e[2]"] = 1
		expectedValues["e[3]"] = 1
		expectedValues["e[4]"] = 0
		expectedValues["e[5]"] = 0
		expectedValues["e[6]"] = 0
		expectedValues["e[7]"] = 0
		assert.Solved(r1csBN256, good, expectedValues)
	}

}
