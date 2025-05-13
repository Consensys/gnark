package gkrapi

import (
	"testing"

	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/stretchr/testify/assert"
)

func TestCompile2Cycles(t *testing.T) {
	var d = gkrinfo.StoringInfo{
		Dependencies: [][]gkrinfo.InputDependency{
			nil,
			{
				{
					OutputWire:     0,
					OutputInstance: 1,
					InputInstance:  0,
				},
			},
		},
		Circuit: gkrinfo.Circuit{
			{
				Inputs: []int{1},
			},
			{
				Inputs: []int{},
			},
		},
	}

	expectedCompiled := gkrinfo.StoringInfo{
		Dependencies: [][]gkrinfo.InputDependency{
			{{
				OutputWire:     1,
				OutputInstance: 0,
				InputInstance:  1,
			}},
			nil,
		},
		Circuit: gkrinfo.Circuit{
			{
				Inputs:          []int{},
				NbUniqueOutputs: 1,
			},
			{
				Inputs: []int{0},
			}},
		NbInstances: 2,
	}

	expectedPermutations := gkrinfo.Permutations{
		SortedInstances:      []int{1, 0},
		SortedWires:          []int{1, 0},
		InstancesPermutation: []int{1, 0},
		WiresPermutation:     []int{1, 0},
	}

	p, err := d.Compile(2)
	assert.NoError(t, err)
	assert.Equal(t, expectedPermutations, p)
	assert.Equal(t, expectedCompiled, d)
}

func TestCompile3Cycles(t *testing.T) {
	var d = gkrinfo.StoringInfo{
		Dependencies: [][]gkrinfo.InputDependency{
			nil,
			{
				{
					OutputWire:     0,
					OutputInstance: 2,
					InputInstance:  0,
				},
				{
					OutputWire:     0,
					OutputInstance: 1,
					InputInstance:  2,
				},
			},
			nil,
		},
		Circuit: gkrinfo.Circuit{
			{
				Inputs: []int{2},
			},
			{
				Inputs: []int{},
			},
			{
				Inputs: []int{1},
			},
		},
	}

	expectedCompiled := gkrinfo.StoringInfo{
		Dependencies: [][]gkrinfo.InputDependency{
			{{
				OutputWire:     2,
				OutputInstance: 0,
				InputInstance:  1,
			}, {
				OutputWire:     2,
				OutputInstance: 1,
				InputInstance:  2,
			}},

			nil,
			nil,
		},
		Circuit: gkrinfo.Circuit{
			{
				Inputs:          []int{},
				NbUniqueOutputs: 1,
			},
			{
				Inputs:          []int{0},
				NbUniqueOutputs: 1,
			},
			{
				Inputs:          []int{1},
				NbUniqueOutputs: 0,
			},
		},
		NbInstances: 3, // not allowed if we were actually performing gkr
	}

	expectedPermutations := gkrinfo.Permutations{
		SortedInstances:      []int{1, 2, 0},
		SortedWires:          []int{1, 2, 0},
		InstancesPermutation: []int{2, 0, 1},
		WiresPermutation:     []int{2, 0, 1},
	}

	p, err := d.Compile(3)
	assert.NoError(t, err)
	assert.Equal(t, expectedPermutations, p)
	assert.Equal(t, expectedCompiled, d)
}
