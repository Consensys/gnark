package bits_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

type toNAFCircuit struct {
	A                  frontend.Variable
	B0, B1, B2, B3, B4 frontend.Variable
}

func (c *toNAFCircuit) Define(api frontend.API) error {
	// to binary
	b := bits.ToNAF(api, c.A, bits.WithNbDigits(6))
	api.AssertIsEqual(b[0], c.B0)
	api.AssertIsEqual(b[1], c.B1)
	api.AssertIsEqual(b[2], c.B2)
	api.AssertIsEqual(b[3], c.B3)
	api.AssertIsEqual(b[4], c.B4)
	api.AssertIsEqual(b[5], 0)

	return nil
}

func TestToNAF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&toNAFCircuit{}, &toNAFCircuit{A: 13, B0: 1, B1: 0, B2: -1, B3: 0, B4: 1})
}
