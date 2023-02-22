package selector

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

func init() {
	// register hints
	hint.Register(StepOutput)
}

// Partition selects left or right side of the input array, with respect to the pivotPosition.
// More precisely when rightSide is false, for each i:
//
//	if i < pivotPosition
//	    out[i] = input[i]
//	else
//	    out[i] = 0
//
// and when rightSide is true, for each i we have:
//
//	if i >= pivotPosition
//	    out[i] = input[i]
//	else
//	    out[i] = 0
//
// We must have pivotPosition >= 1 and pivotPosition <= len(input)-1, otherwise no proof can be generated.
func Partition(api frontend.API, pivotPosition frontend.Variable, rightSide bool,
	input []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(input))
	var mask []frontend.Variable
	if rightSide {
		mask = StepMask(api, len(input), pivotPosition, 0, 1)
	} else {
		mask = StepMask(api, len(input), pivotPosition, 1, 0)
	}
	for i := 0; i < len(out); i++ {
		out[i] = api.Mul(mask[i], input[i])
	}
	return out
}

func StepMask(api frontend.API, outputLen int,
	stepPosition, startValue, endValue frontend.Variable) []frontend.Variable {
	if outputLen < 2 {
		panic("output len must be >= 2")
	}
	// Get the output as a hint
	out, _ := api.Compiler().NewHint(StepOutput, outputLen, stepPosition, startValue, endValue)

	// Add boundary constraints
	api.AssertIsEqual(out[0], startValue)
	api.AssertIsEqual(out[len(out)-1], endValue)

	// Add constraints for the correct form of a step function that steps at the stepPosition
	for i := 1; i < len(out); i++ {
		// (out[i] - out[i-1]) * (i - stepPosition) == 0
		api.AssertIsEqual(api.Mul(api.Sub(out[i], out[i-1]), api.Sub(i, stepPosition)), 0)
	}
	return out
}

// StepOutput is a hint function used within [StepMask] function. It must be
// provided to the prover when circuit uses it.
func StepOutput(_ *big.Int, inputs, results []*big.Int) error {
	stepPos := inputs[0]
	startValue := inputs[1]
	endValue := inputs[2]
	for i := 0; i < len(results); i++ {
		if i < int(stepPos.Int64()) {
			results[i].Set(startValue)
		} else {
			results[i].Set(endValue)
		}
	}
	return nil
}
