package bits

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type toBinaryCircuit struct {
	A          frontend.Variable
	B0, B1, B2 frontend.Variable
}

func (c *toBinaryCircuit) Define(api frontend.API) error {
	// binary decomposition
	nA := FromBinary(api, c.B0, c.B1, c.B2)
	oA := api.FromBinary(c.B0, c.B1, c.B2)

	api.AssertIsEqual(nA, oA)
	api.AssertIsEqual(nA, c.A)

	// to binary
	b := ToBinary(api, c.A, WithNbDigits(3))
	api.AssertIsEqual(b[0], c.B0)
	api.AssertIsEqual(b[1], c.B1)
	api.AssertIsEqual(b[2], c.B2)

	return nil
}

func TestToBinary(t *testing.T) {
	// TODO

	assert := test.NewAssert(t)

	assert.ProverSucceeded(&toBinaryCircuit{}, &toBinaryCircuit{A: 5, B0: 1, B1: 0, B2: 1})
}
