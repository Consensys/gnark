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

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(gurvy.BN256, &cubicCircuit)
	assert.NoError(err)

	{
		var witness CubicCircuit
		witness.X.Assign(42)
		witness.Y.Assign(42)

		assert.NotSolved(r1cs, &witness)
	}

	{
		var witness CubicCircuit
		witness.X.Assign(3)
		witness.Y.Assign(35)
		assert.Solved(r1cs, &witness)
	}

}
