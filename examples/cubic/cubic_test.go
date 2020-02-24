package main

import (
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/groth16"
)

func TestCubicEquation(t *testing.T) {
	assert := groth16.NewAssert(t)
	circuit := New() // x**3+x+5 == y

	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Secret, "x", 42)
		bad.Assign(cs.Public, "y", 42)
		assert.NotSolved(circuit, bad)
	}

	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Public, "x", 3) // x should be Secret
		bad.Assign(cs.Public, "y", 35)
		assert.NotSolved(circuit, bad)
	}

	{
		good := cs.NewAssignment()
		good.Assign(cs.Secret, "x", 3)
		good.Assign(cs.Public, "y", 35)
		expectedValues := make(map[string]interface{})
		expectedValues["x^3"] = 27
		expectedValues["x"] = 3
		assert.Solved(circuit, good, expectedValues)
	}

}

func BenchmarkCubicEquation(b *testing.B) {
	circuit := New() // x**3+x+5 == y

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 3)
	good.Assign(cs.Public, "y", 35)

	groth16.BenchmarkSetup(b, circuit)
	groth16.BenchmarkProver(b, circuit, good)
	groth16.BenchmarkVerifier(b, circuit, good)
}
