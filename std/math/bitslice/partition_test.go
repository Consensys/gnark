package bitslice

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type partitionCircuit struct {
	Split                  uint
	In, ExpLower, ExpUpper frontend.Variable
}

func (c *partitionCircuit) Define(api frontend.API) error {
	lower, upper := Partition(api, c.In, c.Split)
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
