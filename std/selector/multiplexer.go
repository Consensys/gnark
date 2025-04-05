// Package selector provides a lookup table and map, based on linear scan.
//
// The native [frontend.API] provides 1- and 2-bit lookups through the interface
// methods Select and Lookup2. This package extends the lookups to
// arbitrary-sized vectors. The lookups can be performed using the index of the
// elements (function [Mux]) or using a key, for which the user needs to provide
// the slice of keys (function [Map]).
//
// The implementation uses linear scan over all inputs.
package selector

import (
	"fmt"
	"math/big"
	binary "math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
)

func init() {
	// register hints
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in this package. This method is
// useful for registering all hints in the solver.
func GetHints() []solver.Hint {
	return []solver.Hint{stepOutput, muxIndicators, mapIndicators}
}

// Map is a key value associative array: the output will be values[i] such that
// keys[i] == queryKey. If keys does not contain queryKey, no proofs can be
// generated. If keys has more than one key that equals to queryKey, the output
// will be undefined, and the output could be any linear combination of all the
// corresponding values with that queryKey.
//
// In case keys and values do not have the same length, this function will
// panic.
func Map(api frontend.API, queryKey frontend.Variable,
	keys []frontend.Variable, values []frontend.Variable) frontend.Variable {
	// we don't need this check, but we added it to produce more informative errors
	// and disallow len(keys) < len(values) which is supported by generateSelector.
	if len(keys) != len(values) {
		panic(fmt.Sprintf("The number of keys and values must be equal (%d != %d)", len(keys), len(values)))
	}
	return dotProduct(api, values, KeyDecoder(api, queryKey, keys))
}

// Mux is an n to 1 multiplexer: out = inputs[sel]. In other words, it selects
// exactly one of its inputs based on sel. The index of inputs starts from zero.
//
// sel needs to be between 0 and n - 1 (inclusive), where n is the number of
// inputs, otherwise the proof will fail.
func Mux(api frontend.API, sel frontend.Variable, inputs ...frontend.Variable) frontend.Variable {
	n := uint(len(inputs))
	if n == 1 {
		api.AssertIsEqual(sel, 0)
		return inputs[0]
	}
	nbBits := binary.Len(n - 1)                                   // we use n-1 as sel is 0-indexed
	selBits := bits.ToBinary(api, sel, bits.WithNbDigits(nbBits)) // binary decomposition ensures sel < 2^nbBits

	// We use BinaryMux when len(inputs) is a power of 2.
	if binary.OnesCount(n) == 1 {
		return BinaryMux(api, selBits, inputs)
	}

	bcmp := cmp.NewBoundedComparator(api, big.NewInt((1<<nbBits)-1), false)
	bcmp.AssertIsLessEq(sel, n-1)

	// Otherwise, we split inputs into two sub-arrays, such that the first part's length is 2's power
	return muxRecursive(api, selBits, inputs)
}

func muxRecursive(api frontend.API,
	selBits []frontend.Variable, inputs []frontend.Variable) frontend.Variable {

	nbBits := len(selBits)
	leftCount := uint(1 << (nbBits - 1))
	left := BinaryMux(api, selBits[:nbBits-1], inputs[:leftCount])

	rightCount := uint(len(inputs)) - leftCount
	nbRightBits := binary.Len(rightCount)

	var right frontend.Variable
	if binary.OnesCount(rightCount) == 1 {
		right = BinaryMux(api, selBits[:nbRightBits-1], inputs[leftCount:])
	} else {
		right = muxRecursive(api, selBits[:nbRightBits], inputs[leftCount:])
	}

	msb := selBits[nbBits-1]
	return api.Select(msb, right, left)
}

// KeyDecoder is a decoder that associates keys to its output wires. It outputs
// 1 on the wire that is associated to a key that equals to queryKey. In other
// words:
//
//	if keys[i] == queryKey
//	    out[i] = 1
//	else
//	    out[i] = 0
//
// If keys has more than one key that equals to queryKey, the output is
// undefined. However, the output is guaranteed to be zero for the wires that
// are associated with a key which is not equal to queryKey.
func KeyDecoder(api frontend.API, queryKey frontend.Variable, keys []frontend.Variable) []frontend.Variable {
	return generateDecoder(api, false, 0, queryKey, keys)
}

// Decoder is a decoder with n outputs. It outputs 1 on the wire with index sel,
// and 0 otherwise. Indices start from zero. In other words:
//
//	if i == sel
//	    out[i] = 1
//	else
//	    out[i] = 0
//
// sel needs to be between 0 and n - 1 (inclusive) otherwise no proof can be
// generated.
func Decoder(api frontend.API, n int, sel frontend.Variable) []frontend.Variable {
	return generateDecoder(api, true, n, sel, nil)
}

// generateDecoder generates a circuit for a decoder which indicates the
// selected index. If sequential is true, an ordinary decoder of size n is
// generated, and keys are ignored. If sequential is false, a key based decoder
// is generated, and len(keys) is used to determine the size of the output. n
// will be ignored in this case.
func generateDecoder(api frontend.API, sequential bool, n int, sel frontend.Variable,
	keys []frontend.Variable) []frontend.Variable {

	var indicators []frontend.Variable
	var err error
	if sequential {
		indicators, err = api.Compiler().NewHint(muxIndicators, n, sel)
	} else {
		indicators, err = api.Compiler().NewHint(mapIndicators, len(keys), append(keys, sel)...)
	}
	if err != nil {
		panic(fmt.Sprintf("error in calling Mux/Map hint: %v", err))
	}

	indicatorsSum := frontend.Variable(0)
	for i := 0; i < len(indicators); i++ {
		// Check that all indicators for inputs that are not selected, are zero.
		if sequential {
			// indicators[i] * (sel - i) == 0
			api.AssertIsEqual(api.Mul(indicators[i], api.Sub(sel, i)), 0)
		} else {
			// indicators[i] * (sel - keys[i]) == 0
			api.AssertIsEqual(api.Mul(indicators[i], api.Sub(sel, keys[i])), 0)
		}
		indicatorsSum = api.Add(indicatorsSum, indicators[i])
	}
	// We need to check that the indicator of the selected input is exactly 1. We
	// use a sum constraint, because usually it is cheap.
	api.AssertIsEqual(indicatorsSum, 1)
	return indicators
}

func dotProduct(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	out := frontend.Variable(0)
	for i := 0; i < len(a); i++ {
		// out += indicators[i] * values[i]
		out = api.MulAcc(out, a[i], b[i])
	}
	return out
}

// muxIndicators is a hint function used within [Mux] function. It must be
// provided to the prover when circuit uses it.
func muxIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	sel := inputs[0]
	for i := 0; i < len(results); i++ {
		// i is an int which can be int32 or int64. We convert i to int64 then to
		// bigInt, which is safe. We should not convert sel to int64.
		if sel.Cmp(big.NewInt(int64(i))) == 0 {
			results[i].SetUint64(1)
		} else {
			results[i].SetUint64(0)
		}
	}
	return nil
}

// mapIndicators is a hint function used within [Map] function. It must be
// provided to the prover when circuit uses it.
func mapIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	key := inputs[len(inputs)-1]
	// We must make sure that we are initializing all elements of results
	for i := 0; i < len(results); i++ {
		if key.Cmp(inputs[i]) == 0 {
			results[i].SetUint64(1)
		} else {
			results[i].SetUint64(0)
		}
	}
	return nil
}
