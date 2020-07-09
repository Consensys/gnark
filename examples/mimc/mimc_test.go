package main

import (
	"testing"

	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/groth16"
)

func TestPreimage(t *testing.T) {

	assert := groth16.NewAssert(t)

	r1cs := New()
	r1csBN256 := r1cs.ToR1CS(gurvy.BN256)

	{
		bad := make(map[string]interface{})
		bad["h"] = 42
		bad["pi"] = 42
		assert.NotSolved(r1csBN256, bad)
	}

	{
		good := make(map[string]interface{})
		good["pi"] = 35
		good["h"] = "19226210204356004706765360050059680583735587569269469539941275797408975356275"
		assert.Solved(r1csBN256, good, nil)
	}

}
