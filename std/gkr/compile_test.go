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
