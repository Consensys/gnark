package main

import (
	"testing"

	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestPreimage(t *testing.T) {
	assert := groth16.NewAssert(t)

	var mimcCircuit MiMCCircuit

	r1cs, err := frontend.Compile(gurvy.BN256, &mimcCircuit)
	assert.NoError(err)

	{
		mimcCircuit.Hash.Assign(42)
		mimcCircuit.PreImage.Assign(42)
		assert.NotSolved(r1cs, &mimcCircuit)
	}

	{
		mimcCircuit.PreImage.Assign(35)
		mimcCircuit.Hash.Assign("19226210204356004706765360050059680583735587569269469539941275797408975356275")
		assert.Solved(r1cs, &mimcCircuit, nil)
	}

}
