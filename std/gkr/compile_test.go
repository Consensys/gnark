package gkr

import (
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConvertCircuit(t *testing.T) {
	circuitNoPtr := circuitNoPtr{
		{
			assignments:     []frontend.Variable{1, 2},
			inputs:          []int{},
			nbUniqueOutputs: 1,
		},
		{
			assignments:     []frontend.Variable{2, 3},
			inputs:          []int{},
			nbUniqueOutputs: 1,
		},
		{
			gate:            MulGate{},
			inputs:          []int{0, 1},
			dependencies:    nil,
			nbUniqueOutputs: 0,
		},
	}
	circuit := bn254ConvertCircuit(circuitNoPtr)
	assert.Equal(t, 3, len(circuit))
}

func TestNoPtrCompile(t *testing.T) {
	var d = circuitDataNoPtr{
		circuit: circuitNoPtr{
			{
				assignments:  []frontend.Variable{2, 1},
				inputs:       []int{1},
				dependencies: nil,
			},
			{
				assignments: []frontend.Variable{nil, 0},
				inputs:      []int{},
				dependencies: []inputDependency{
					{
						outputWire:     0,
						outputInstance: 1,
						inputInstance:  0,
					},
				},
			},
		},
	}
	expectedCompiled := circuitDataNoPtr{
		circuit: circuitNoPtr{
			{
				assignments: []frontend.Variable{0, nil},
				inputs:      []int{},
				dependencies: []inputDependency{{
					outputWire:     1,
					outputInstance: 0,
					inputInstance:  1,
				}},

				nbUniqueOutputs: 1,
			},
			{
				assignments:  []frontend.Variable{1, 2},
				inputs:       []int{0},
				dependencies: nil,
			}},
		maxNIns:         1,
		sortedInstances: []int{1, 0},
		sortedWires:     []int{1, 0},
	}

	assert.NoError(t, d.compile())
	assert.Equal(t, expectedCompiled, d)
}
