package selector

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// BinaryMux is a 2^k to 1 multiplexer which uses a binary selector. selBits are
// the selector bits, and the input at the index equal to the binary number
// represented by the selector bits will be selected. More precisely the output
// will be:
//
//	inputs[selBits[0]+selBits[1]*(1<<1)+selBits[2]*(1<<2)+...]
//
// len(inputs) must be 2^len(selBits).
func BinaryMux(api frontend.API, selBits, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) != 1<<len(selBits) {
		panic(fmt.Sprintf("invalid input length for BinaryMux (%d != 2^%d)", len(inputs), len(selBits)))
	}

	for _, b := range selBits {
		api.AssertIsBoolean(b)
	}

	return binaryMuxRecursive(api, selBits, inputs)
}

func binaryMuxRecursive(api frontend.API, selBits, inputs []frontend.Variable) frontend.Variable {
	// The number of defined R1CS constraints for an input of length n is always n - 1.
	// n does not need to be a power of 2.
	if len(selBits) == 0 {
		return inputs[0]
	}

	nextSelBits := selBits[:len(selBits)-1]
	msb := selBits[len(selBits)-1]
	pivot := 1 << len(nextSelBits)
	if pivot >= len(inputs) {
		return binaryMuxRecursive(api, nextSelBits, inputs)
	}

	left := binaryMuxRecursive(api, nextSelBits, inputs[:pivot])
	right := binaryMuxRecursive(api, nextSelBits, inputs[pivot:])
	return api.Add(left, api.Mul(msb, api.Sub(right, left)))
}

// BinaryMuxUnchecked is like BinaryMux but assumes selBits are already
// constrained to be boolean (e.g., from bits.ToBinary). This avoids redundant
// boolean assertions when the same bits are reused across multiple Mux calls.
// len(inputs) must be 2^len(selBits).
func BinaryMuxUnchecked(api frontend.API, selBits, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) != 1<<len(selBits) {
		panic(fmt.Sprintf("invalid input length for BinaryMuxUnchecked (%d != 2^%d)", len(inputs), len(selBits)))
	}
	return binaryMuxRecursive(api, selBits, inputs)
}

// GeneralMuxUnchecked is a multiplexer that handles any number of inputs
// (not just powers of 2). It assumes selBits are already constrained to be
// boolean and that sel < len(inputs) has been verified by the caller.
// This is useful when the same selector bits are reused across multiple Mux calls.
func GeneralMuxUnchecked(api frontend.API, selBits, inputs []frontend.Variable) frontend.Variable {
	return binaryMuxRecursive(api, selBits, inputs)
}
