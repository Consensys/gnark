package selector_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
	"github.com/consensys/gnark/test"
	"testing"
)

type partitionerCircuit struct {
	Pivot     frontend.Variable    `gnark:",public"`
	In        [6]frontend.Variable `gnark:",public"`
	WantLeft  [6]frontend.Variable `gnark:",public"`
	WantRight [6]frontend.Variable `gnark:",public"`
}

func (c *partitionerCircuit) Define(api frontend.API) error {
	gotLeft := selector.Partition(api, c.Pivot, false, c.In[:])
	for i, want := range c.WantLeft {
		api.AssertIsEqual(gotLeft[i], want)
	}

	gotRight := selector.Partition(api, c.Pivot, true, c.In[:])
	for i, want := range c.WantRight {
		api.AssertIsEqual(gotRight[i], want)
	}

	return nil
}

type ignoredOutputPartitionerCircuit struct {
	Pivot frontend.Variable    `gnark:",public"`
	In    [2]frontend.Variable `gnark:",public"`
}

func (c *ignoredOutputPartitionerCircuit) Define(api frontend.API) error {
	_ = selector.Partition(api, c.Pivot, false, c.In[:])
	_ = selector.Partition(api, c.Pivot, true, c.In[:])
	return nil
}

func TestPartition(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     3,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 0, 0, 0},
		WantRight: [6]frontend.Variable{0, 0, 0, 40, 50, 60},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     1,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 0, 0, 0, 0, 0},
		WantRight: [6]frontend.Variable{0, 20, 30, 40, 50, 60},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     5,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 50, 0},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 60},
	})

	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     5,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 0, 0},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 0},
	})

	// Pivot is outside and the prover fails:
	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     6,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantRight: [6]frontend.Variable{0, 0, 0, 0, 0, 0},
	})
	// todo: fails for /bls24_317/plonkFRI#04

	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot:     0,
		In:        [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		WantLeft:  [6]frontend.Variable{0, 0, 0, 0, 0, 0},
		WantRight: [6]frontend.Variable{10, 20, 30, 40, 50, 60},
	})

	// tests by ignoring the output:
	assert.ProverSucceeded(&ignoredOutputPartitionerCircuit{}, &ignoredOutputPartitionerCircuit{
		Pivot: 1,
		In:    [2]frontend.Variable{10, 20},
	})

	assert.ProverFailed(&ignoredOutputPartitionerCircuit{}, &ignoredOutputPartitionerCircuit{
		Pivot: 0,
		In:    [2]frontend.Variable{10, 20},
	})

	assert.ProverFailed(&ignoredOutputPartitionerCircuit{}, &ignoredOutputPartitionerCircuit{
		Pivot: 2,
		In:    [2]frontend.Variable{10, 20},
	})
}
