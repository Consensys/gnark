package keccakf

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type lrotCirc struct {
	In    frontend.Variable
	Shift int
	Out   frontend.Variable
}

func (c *lrotCirc) Define(api frontend.API) error {
	uapi := NewUint64API(api)
	in := uapi.AsUint64(c.In)
	out := uapi.AsUint64(c.Out)
	res := uapi.lrot(in, c.Shift)
	uapi.assertEq(out, res)
	return nil
}

func TestLeftRotation(t *testing.T) {
	assert := test.NewAssert(t)
	// err := test.IsSolved(&lrotCirc{Shift: 2}, &lrotCirc{In: 6, Shift: 2, Out: 24}, ecc.BN254.ScalarField())
	// assert.NoError(err)
	assert.ProverSucceeded(&lrotCirc{Shift: 2}, &lrotCirc{In: 6, Shift: 2, Out: 24})
}
