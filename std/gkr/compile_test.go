package gkr

import (
	"github.com/consensys/gnark/constraint"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCompile2Cycles(t *testing.T) {
	var d = constraint.GkrInfo{
		Circuit: constraint.GkrCircuit{
			{
				Inputs:       []int{1},
				Dependencies: nil,
			},
			{
				Inputs: []int{},
				Dependencies: []constraint.InputDependency{
					{
						OutputWire:     0,
						OutputInstance: 1,
						InputInstance:  0,
					},
				},
			},
		},
	}

	expectedCompiled := constraint.GkrInfo{
		Circuit: constraint.GkrCircuit{
			{
				Inputs: []int{},
				Dependencies: []constraint.InputDependency{{
					OutputWire:     1,
					OutputInstance: 0,
					InputInstance:  1,
				}},

				NbUniqueOutputs: 1,
			},
			{
				Inputs:       []int{0},
				Dependencies: nil,
			}},
		MaxNIns:     1,
		NbInstances: 2,
	}

	expectedPermutations := constraint.GkrPermutations{
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
	var d = constraint.GkrInfo{
		Circuit: constraint.GkrCircuit{
			{
				Inputs:       []int{2},
				Dependencies: nil,
			},
			{
				Inputs: []int{},
				Dependencies: []constraint.InputDependency{
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
			},
			{
				Inputs:       []int{1},
				Dependencies: nil,
			},
		},
	}

	expectedCompiled := constraint.GkrInfo{
		Circuit: constraint.GkrCircuit{
			{
				Inputs: []int{},
				Dependencies: []constraint.InputDependency{{
					OutputWire:     2,
					OutputInstance: 0,
					InputInstance:  1,
				}, {
					OutputWire:     2,
					OutputInstance: 1,
					InputInstance:  2,
				}},
				NbUniqueOutputs: 1,
			},
			{
				Inputs:          []int{0},
				Dependencies:    nil,
				NbUniqueOutputs: 1,
			},
			{
				Inputs:          []int{1},
				Dependencies:    nil,
				NbUniqueOutputs: 0,
			},
		},
		MaxNIns:     1,
		NbInstances: 3, // not allowed if we were actually performing gkr
	}

	expectedPermutations := constraint.GkrPermutations{
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
