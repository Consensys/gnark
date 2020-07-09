package main

import (
	"testing"

	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/bn256/groth16"
)

func TestPreimage(t *testing.T) {

	assert := groth16.NewAssert(t)

	r1cs := New()
	r1csBN256 := r1cs.ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "h", 42)
		bad.Assign(backend.Secret, "pi", 42)
		assert.NotSolved(r1csBN256, bad)
	}

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "h", 3)
		bad.Assign(backend.Public, "pi", 35) // pi should be Secret
		assert.NotSolved(r1csBN256, bad)
	}

	{
		good := backend.NewAssignment()
		good.Assign(backend.Secret, "pi", 35)
		good.Assign(backend.Public, "h", "19226210204356004706765360050059680583735587569269469539941275797408975356275")
		assert.Solved(r1csBN256, good, nil)
	}

}
