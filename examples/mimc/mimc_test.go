package main

import (
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/groth16"
)

func TestPreimage(t *testing.T) {
	assert := groth16.NewAssert(t)
	circuit := New()

	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Public, "h", 42)
		bad.Assign(cs.Secret, "pi", 42)
		assert.NotSolved(circuit, bad)
	}

	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Public, "h", 3)
		bad.Assign(cs.Public, "pi", 35) // pi should be Secret
		assert.NotSolved(circuit, bad)
	}

	{
		good := cs.NewAssignment()
		good.Assign(cs.Secret, "pi", 35)
		good.Assign(cs.Public, "h", "3576610639377770372167309049248361867549136162456161943898479697477337767682")
		assert.Solved(circuit, good, nil)
	}

}
