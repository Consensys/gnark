package gkr

import (
	"github.com/consensys/gnark/constraint"
	"github.com/stretchr/testify/assert"
	"testing"
)

/*func TestConvertCircuit(t *testing.T) {	TODO: Move to cs package
	circuitNoPtr := frontend.GkrCircuit{
		{
			Assignments:     []frontend.Variable{1, 2},
			Inputs:          []int{},
			NbUniqueOutputs: 1,
		},
		{
			Assignments:     []frontend.Variable{2, 3},
			Inputs:          []int{},
			NbUniqueOutputs: 1,
		},
		{
			Gate:            "mul",
			Inputs:          []int{0, 1},
			Dependencies:    nil,
			NbUniqueOutputs: 0,
		},
	}
	circuit := cs.bn254ConvertCircuit(circuitNoPtr)
	assert.Equal(t, 3, len(circuit))
}*/

func TestNoPtrCompile(t *testing.T) {
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
	assignment := GkrAssignment{
		{2, 1},
		{nil, 0},
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
		MaxNIns: 1,
	}
	expectedAssignment := GkrAssignment{
		{0, nil},
		{1, 2},
	}

	_, err := d.Compile(assignment.NbInstances()) // TODO: Test the permutation too
	assert.NoError(t, err)
	assert.Equal(t, expectedCompiled, d)
	assert.Equal(t, expectedAssignment, assignment)
}
