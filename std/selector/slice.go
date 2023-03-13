package selector

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

// Slice selects a slice of the input array at indices [start, end), and zeroes the array at other
// indices. More precisely, for each i we have:
//
//	if i >= start and i < end
//	    out[i] = input[i]
//	else
//	    out[i] = 0
//
// We must have start >= 1 and end <= len(input)-1, otherwise a proof can not be generated.
func Slice(api frontend.API, start, end frontend.Variable, input []frontend.Variable) []frontend.Variable {
	// it appears that this is the most efficient implementation. There is also another implementation
	// which creates the mask by adding two stepMask outputs, however that would not work correctly when
	// end < start.
	out := Partition(api, end, false, input)
	out = Partition(api, start, true, out)
	return out
}

// Partition selects left or right side of the input array, with respect to the pivotPosition.
// More precisely when rightSide is false, for each i we have:
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
// We must have pivotPosition >= 1 and pivotPosition <= len(input)-1, otherwise a proof cannot be generated.
func Partition(api frontend.API, pivotPosition frontend.Variable, rightSide bool,
	input []frontend.Variable) (out []frontend.Variable) {
	out = make([]frontend.Variable, len(input))
	var mask []frontend.Variable
	// we create a bit mask to multiply with the input, if we create a bigger mask, we can handle
	// pivotPosition == 0 or pivotPosition == len(input), but that will add extra constraints.
	if rightSide {
		mask = stepMask(api, len(input), pivotPosition, 0, 1)
	} else {
		mask = stepMask(api, len(input), pivotPosition, 1, 0)
	}
	for i := 0; i < len(out); i++ {
		out[i] = api.Mul(mask[i], input[i])
	}
	return
}

// stepMask generates a step like function into an output array of a given length.
// The output is an array of length outputLen,
// such that its first stepPosition elements are equal to startValue and the remaining elements are equal to
// endValue. Note that outputLen cannot be a circuit variable.
//
// We must have stepPosition >= 1 and stepPosition <= outputLen, otherwise a proof cannot be generated.
// This function panics when outputLen is less than 2.
func stepMask(api frontend.API, outputLen int,
	stepPosition, startValue, endValue frontend.Variable) []frontend.Variable {
	if outputLen < 2 {
		panic("the output len of StepMask must be >= 2")
	}
	// get the output as a hint
	out, err := api.Compiler().NewHint(stepOutput, outputLen, stepPosition, startValue, endValue)
	if err != nil {
		panic(fmt.Sprintf("error in calling StepMask hint: %v", err))
	}

	// add the boundary constraints
	api.AssertIsEqual(out[0], startValue)
	api.AssertIsEqual(out[len(out)-1], endValue)

	// add constraints for the correct form of a step function that steps at the stepPosition
	for i := 1; i < len(out); i++ {
		// (out[i] - out[i-1]) * (i - stepPosition) == 0
		api.AssertIsEqual(api.Mul(api.Sub(out[i], out[i-1]), api.Sub(i, stepPosition)), 0)
	}
	return out
}

// stepOutput is a hint function used within [StepMask] function. It must be
// provided to the prover when circuit uses it.
func stepOutput(_ *big.Int, inputs, results []*big.Int) error {
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
