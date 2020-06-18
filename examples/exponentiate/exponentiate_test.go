package main

import (
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/bn256/groth16"
	"github.com/consensys/gurvy/bn256/fr"
)

func TestExponentiate(t *testing.T) {

	assert := groth16.NewAssert(t)

	r1cs := New() // y == x**e, captures the geometry of the circuit, not tied to any curve.

	r1csBN256 := backend_bn256.Cast(r1cs)

	// TODO bigger numbers
	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "x", 2)
		bad.Assign(backend.Secret, "e", 12)
		bad.Assign(backend.Public, "y", 4095) // y != x**e
		assert.NotSolved(&r1csBN256, bad)
	}

	{
		bad := backend.NewAssignment()
		bad.Assign(backend.Public, "x", 2)
		bad.Assign(backend.Public, "e", 12) // e should be Secret
		bad.Assign(backend.Public, "y", 4096)
		assert.NotSolved(&r1csBN256, bad)
	}

	{
		good := backend.NewAssignment()
		good.Assign(backend.Public, "x", 2)
		good.Assign(backend.Secret, "e", 12)
		good.Assign(backend.Public, "y", 4096)
		expectedValues := make(map[string]fr.Element)
		bindec := make([]fr.Element, 8)
		bindec[0].SetUint64(0)
		bindec[1].SetUint64(0)
		bindec[2].SetUint64(1)
		bindec[3].SetUint64(1)
		bindec[4].SetUint64(0)
		bindec[5].SetUint64(0)
		bindec[6].SetUint64(0)
		bindec[7].SetUint64(0)
		expectedValues["e[0]"] = bindec[0]
		expectedValues["e[1]"] = bindec[1]
		expectedValues["e[2]"] = bindec[2]
		expectedValues["e[3]"] = bindec[3]
		expectedValues["e[4]"] = bindec[4]
		expectedValues["e[5]"] = bindec[5]
		expectedValues["e[6]"] = bindec[6]
		expectedValues["e[7]"] = bindec[7]
		assert.Solved(&r1csBN256, good, expectedValues)
	}

}
