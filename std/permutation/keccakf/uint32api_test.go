package keccakf

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type rShiftUint32Circ struct {
	In1 frontend.Variable
	In2 int
	Out frontend.Variable
}

type rRotateUint32Circ struct {
	In1 frontend.Variable
	In2 int
	Out frontend.Variable
}

func (c *rShiftUint32Circ) Define(api frontend.API) error {
	uapi := NewUint32API(api)
	in1 := uapi.AsUint32(c.In1)
	out := uapi.AsUint32(c.Out)
	res := uapi.Rshift(in1, c.In2)
	uapi.assertEq(out, res)
	return nil
}

func (c *rRotateUint32Circ) Define(api frontend.API) error {
	uapi := NewUint32API(api)
	in1 := uapi.AsUint32(c.In1)
	out := uapi.AsUint32(c.Out)
	res := uapi.Rrot(in1, c.In2)
	uapi.assertEq(out, res)
	return nil
}

func TestRshiftOperation(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &rShiftUint32Circ{In2: 10, Out: 844508}
	witness := &rShiftUint32Circ{In1: 864777201, In2: 10, Out: 844508}
	assert.ProverSucceeded(circuit, witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

func TestRrotateOperation(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &rRotateUint32Circ{In2: 18, Out: 3707522274}
	witness := &rRotateUint32Circ{In1: 864777201, In2: 18, Out: 3707522274}
	assert.ProverSucceeded(circuit, witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
