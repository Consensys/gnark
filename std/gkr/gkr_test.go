package gkr

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/polynomial"
)

type NoGateGkrVerifierCircuit struct {
	Input  []frontend.Variable
	Output []frontend.Variable `gnark:",public"`
	Proof  Proof
}

/*func (c *NoGateGkrVerifierCircuit) Define(api frontend.API) {

	gkrCircuit := Circuit{
		{ //layer
			{ //wire
				Inputs:     []*Wire{},
				NumOutputs: 1,
				Gate:       nil,
			},
		},
	}

	assignment := WireAssignment{&gkrCircuit[0][0]: int64SliceToMultiLin(c.InputAssignments[0])}

	proverGkrCircuit, proverAssignment
}

func TestNoGateTwoInstances(t *testing.T) {

	inputAssignments := [][]int64{{4, 3}}

}*/

func int64SliceToVariableSlice(int64Slice []int64) (variableSlice []frontend.Variable) {
	variableSlice = make([]frontend.Variable, 0, len(int64Slice))

	for _, v := range int64Slice {
		variableSlice = append(variableSlice, v)
	}

	return
}

func int64SliceToMultiLin(int64Slice []int64) polynomial.MultiLin { //Only semantics
	return int64SliceToVariableSlice(int64Slice)
}
