package main

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

func TestExponentiate(t *testing.T) {
	assert := groth16.NewAssert(t)

	var expCircuit ExponentiateCircuit
	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(gurvy.BN256, &expCircuit)
	if err != nil {
		t.Fatal(err)
	}

	// TODO bigger numbers
	{
		var witness ExponentiateCircuit
		witness.X.Assign(2)
		witness.E.Assign(12)
		witness.Y.Assign(4095)
		assert.NotSolved(r1cs, &witness) // y != x**e
	}

	{
		var witness ExponentiateCircuit
		witness.X.Assign(2)
		witness.E.Assign(12)
		witness.Y.Assign(4096)
		expectedValues := make(map[string]interface{})
		expectedValues["e[0]"] = 0
		expectedValues["e[1]"] = 0
		expectedValues["e[2]"] = 1
		expectedValues["e[3]"] = 1
		expectedValues["e[4]"] = 0
		expectedValues["e[5]"] = 0
		expectedValues["e[6]"] = 0
		expectedValues["e[7]"] = 0
		assert.Solved(r1cs, &witness, expectedValues)
	}

}
