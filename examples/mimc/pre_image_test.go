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
		bad.Assign(cs.Secret, "pi", 42)
		bad.Assign(cs.Public, "h", 42)
		assert.NotSolved(circuit, bad)
	}

	{
		bad := cs.NewAssignment()
		bad.Assign(cs.Public, "pi", 3) // pi should be Secret
		bad.Assign(cs.Public, "h", 35)
		assert.NotSolved(circuit, bad)
	}

	{
		good := cs.NewAssignment()
		knownPi := "3576610639377770372167309049248361867549136162456161943898479697477337767682"
		good.Assign(cs.Secret, "pi", knownPi)
		good.Assign(cs.Public, "h", 35)
		expectedValues := make(map[string]interface{})
		expectedValues["pi"] = knownPi
		expectedValues["h"] = 35
		assert.Solved(circuit, good, expectedValues)
	}

}
