package bitslice

import (
	"testing"

	"github.com/consensys/gnark/backend"
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
	// TODO: for some reason next fails with PLONK+FRI
	assert.ProverSucceeded(&partitionCircuit{Split: 16}, &partitionCircuit{Split: 16, ExpUpper: 0xffff, ExpLower: 0x1234, In: 0xffff1234}, test.WithBackends(backend.GROTH16, backend.PLONK))
	assert.ProverSucceeded(&partitionCircuit{Split: 0}, &partitionCircuit{Split: 0, ExpUpper: 0xffff1234, ExpLower: 0, In: 0xffff1234}, test.WithBackends(backend.GROTH16, backend.PLONK))
	assert.ProverSucceeded(&partitionCircuit{Split: 32}, &partitionCircuit{Split: 32, ExpUpper: 0, ExpLower: 0xffff1234, In: 0xffff1234}, test.WithBackends(backend.GROTH16, backend.PLONK))
	assert.ProverSucceeded(&partitionCircuit{Split: 4}, &partitionCircuit{Split: 4, ExpUpper: 0xffff123, ExpLower: 4, In: 0xffff1234}, test.WithBackends(backend.GROTH16, backend.PLONK))
}
