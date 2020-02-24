package main

import (
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/groth16"
)

func TestExponentiate(t *testing.T) {
	assert := groth16.NewAssert(t)
	circuit := New() // y == x**e

	// TODO bigger numbers
	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Public, "x", 2)
		bad.Assign(cs.Secret, "e", 12)
		bad.Assign(cs.Public, "y", 4095) // y != x**e
		assert.NotSolved(circuit, bad)
	}

	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Public, "x", 2)
		bad.Assign(cs.Public, "e", 12) // e should be Secret
		bad.Assign(cs.Public, "y", 4096)
		assert.NotSolved(circuit, bad)
	}

	{
		good := cs.NewAssignment()
		good.Assign(cs.Public, "x", 2)
		good.Assign(cs.Secret, "e", 12)
		good.Assign(cs.Public, "y", 4096)
		expectedValues := make(map[string]interface{})
		expectedValues["e[0]"] = 0
		expectedValues["e[1]"] = 0
		expectedValues["e[2]"] = 1
		expectedValues["e[3]"] = 1
		expectedValues["e[4]"] = 0
		expectedValues["e[5]"] = 0
		expectedValues["e[6]"] = 0
		expectedValues["e[7]"] = 0
		assert.Solved(circuit, good, expectedValues)
	}

}

func BenchmarkExponentiate(b *testing.B) {
	circuit := New() // y == x**e

	good := cs.NewAssignment()
	good.Assign(cs.Public, "x", 2)
	good.Assign(cs.Secret, "e", 12)
	good.Assign(cs.Public, "y", 4096)

	groth16.BenchmarkSetup(b, circuit)
	groth16.BenchmarkProver(b, circuit, good)
	groth16.BenchmarkVerifier(b, circuit, good)
}
