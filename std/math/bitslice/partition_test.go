package bitslice_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/test"
)

// TODO: add option for choosing nbDigits

type partitionCircuit struct {
	Split                  uint
	In, ExpLower, ExpUpper frontend.Variable

	nbDigitsOpt int
}

func (c *partitionCircuit) Define(api frontend.API) error {
	var opts []bitslice.Option
	if c.nbDigitsOpt > 0 {
		opts = append(opts, bitslice.WithNbDigits(c.nbDigitsOpt))
	}
	lower, upper := bitslice.Partition(api, c.In, c.Split, opts...)
	api.AssertIsEqual(lower, c.ExpLower)
	api.AssertIsEqual(upper, c.ExpUpper)
	return nil
}

func TestPartition(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&partitionCircuit{Split: 0}, test.WithValidAssignment(&partitionCircuit{Split: 0, ExpUpper: 0xffff1234, ExpLower: 0, In: 0xffff1234}))
	assert.CheckCircuit(&partitionCircuit{Split: 4}, test.WithValidAssignment(&partitionCircuit{Split: 4, ExpUpper: 0xffff123, ExpLower: 4, In: 0xffff1234}))
	assert.CheckCircuit(&partitionCircuit{Split: 16}, test.WithValidAssignment(&partitionCircuit{Split: 16, ExpUpper: 0xffff, ExpLower: 0x1234, In: 0xffff1234}))
	assert.CheckCircuit(&partitionCircuit{Split: 32}, test.WithValidAssignment(&partitionCircuit{Split: 32, ExpUpper: 0, ExpLower: 0xffff1234, In: 0xffff1234}))
}

func TestIssue1153(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&partitionCircuit{Split: 8, nbDigitsOpt: 16}, test.WithInvalidAssignment(&partitionCircuit{ExpUpper: 0xff1, ExpLower: 0x21, In: 0xff121}))
}
