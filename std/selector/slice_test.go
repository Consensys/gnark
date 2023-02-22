package selector_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
	"github.com/consensys/gnark/test"
	"testing"
)

type partitionerCircuit struct {
	Pivot frontend.Variable
	In    [6]frontend.Variable
	Left  [6]frontend.Variable
	Right [6]frontend.Variable
}

func (c *partitionerCircuit) Define(api frontend.API) error {
	left := selector.Partition(api, c.Pivot, false, c.In[:])
	for i, want := range c.Left {
		api.AssertIsEqual(want, left[i])
	}
	right := selector.Partition(api, c.Pivot, true, c.In[:])
	for i, want := range c.Right {
		api.AssertIsEqual(want, right[i])
	}
	return nil
}

func TestPartition(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot: 3,
		In:    [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		Left:  [6]frontend.Variable{10, 20, 30, 0, 0, 0},
		Right: [6]frontend.Variable{0, 0, 0, 40, 50, 60},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot: 1,
		In:    [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		Left:  [6]frontend.Variable{10, 0, 0, 0, 0, 0},
		Right: [6]frontend.Variable{0, 20, 30, 40, 50, 60},
	})

	assert.ProverSucceeded(&partitionerCircuit{}, &partitionerCircuit{
		Pivot: 5,
		In:    [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		Left:  [6]frontend.Variable{10, 20, 30, 40, 50, 0},
		Right: [6]frontend.Variable{0, 0, 0, 0, 0, 60},
	})

	// Pivot is outside and the prover fails: (todo: this doesn't work. why?)
	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot: 6,
		In:    [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		Left:  [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		Right: [6]frontend.Variable{0, 0, 0, 0, 0, 0},
	})

	assert.ProverFailed(&partitionerCircuit{}, &partitionerCircuit{
		Pivot: 0,
		In:    [6]frontend.Variable{10, 20, 30, 40, 50, 60},
		Left:  [6]frontend.Variable{0, 0, 0, 0, 0, 0},
		Right: [6]frontend.Variable{10, 20, 30, 40, 50, 60},
	})

}
