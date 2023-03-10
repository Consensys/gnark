package cmp

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	frontend "github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"math/big"
)

func init() {
	// register hints
	RegisterAllHints()
}

// RegisterAllHints registers all the hint functions that are used by this package by calling
// solver.RegisterHint.
func RegisterAllHints() {
	solver.RegisterHint(minOutputHint)
	solver.RegisterHint(isLessOutputHint)
}

// BoundedComparator provides comparison methods, with relatively low circuit complexity, for
// comparing two numbers a and b, when an upper bound for their absolute difference (|a - b|) is
// known. These methods perform only one binary conversion of length: absDiffUppBitLen.
//
// Let's denote the upper bound of the absolute difference of a and b, with ADU, such that we have
// |a - b| <= ADU. The absDiffUppBitLen must be the number of bits of the binary representation of
// ADU. In other words, we must have |a - b| <= 2^absDiffUppBitLen - 1. Lower values of
// absDiffUppBitLen will reduce the number of generated constraints.
//
// As long as |a - b| <= 2^absDiffUppBitLen - 1, all the methods of BoundedComparator work correctly.
// If |a - b| = 2^absDiffUppBitLen, either a proof can not be generated or the methods work
// correctly. If |a - b| > 2^absDiffUppBitLen, as long as |a - b| <= (P - 1) / 2, where P is the
// prime order of the underlying field, no proofs can be generated.
//
// When |a - b| > (P - 1) / 2, the behaviour of the exported methods of BoundedComparator will be
// undefined.
type BoundedComparator struct {
	// the number of bits in the binary representation of the upper bound of the absolute difference
	absDiffUppBitLen int
	api              frontend.API

	// we will use value receiver for methods of this struct,
	// since: 1) the struct is small. 2) methods should not modify any fields.
}

// NewComparator creates a new BoundedComparator.
//
// This function panics if the provided value for absDiffUppBitLen can not be supported by the
// underlying field. Use absDiffUppBitLen = 0 to select the maximum supported value.
func NewComparator(api frontend.API, absDiffUppBitLen int) *BoundedComparator {
	// We need to have |a - b| <= (P - 1) / 2. The BitLen of (P - 1) / 2 is
	// exactly FieldBitLen()-1, so to ensure the inequality, we should have:
	// absDiffUppBitLen <= FieldBitLen()-2
	// todo: by having the order of the field (P) we can implement this with tighter bounds
	if absDiffUppBitLen == 0 {
		absDiffUppBitLen = api.Compiler().FieldBitLen() - 2
	}
	if absDiffUppBitLen > api.Compiler().FieldBitLen()-2 {
		panic("ConfigureComparators: the specified upper bound of absolute difference is too high")
	}
	return &BoundedComparator{
		absDiffUppBitLen: absDiffUppBitLen,
		api:              api,
	}
}

// AssertIsLess defines a set of constraints that can not be satisfied when a >= b.
func (bc BoundedComparator) AssertIsLess(a, b frontend.Variable) {
	// a < b <==> b - a - 1 >= 0
	bits.ToBinary(
		bc.api,
		bc.api.Sub(b, a, 1),
		bits.WithNbDigits(bc.absDiffUppBitLen),
	)
}

// IsLess returns 1 if a < b, and returns 0 if a >= b.
func (bc BoundedComparator) IsLess(a, b frontend.Variable) frontend.Variable {
	res, err := bc.api.Compiler().NewHint(isLessOutputHint, 1, a, b, -1)
	if err != nil {
		panic(fmt.Sprintf("error in calling isLessOutputHint: %v", err))
	}
	indicator := res[0]
	// a < b  <==> b - a - 1 >= 0
	// a >= b <==> a - b >= 0
	bits.ToBinary(
		bc.api,
		bc.api.Select(indicator, bc.api.Sub(b, a, 1), bc.api.Sub(a, b)),
		bits.WithNbDigits(bc.absDiffUppBitLen),
	)
	return indicator
}

// Min returns the minimum of a and b.
func (bc BoundedComparator) Min(a, b frontend.Variable) frontend.Variable {
	res, err := bc.api.Compiler().NewHint(minOutputHint, 1, a, b, -1)
	if err != nil {
		panic(fmt.Sprintf("error in calling minOutputHint: %v", err))
	}
	min := res[0]

	aDiff := bc.api.Sub(a, min)
	bDiff := bc.api.Sub(b, min)

	// (a - min) * (b - min) == 0
	bc.api.AssertIsEqual(0, bc.api.Mul(aDiff, bDiff))

	// (a - min) + (b - min) >= 0
	bits.ToBinary(bc.api, bc.api.Add(aDiff, bDiff), bits.WithNbDigits(bc.absDiffUppBitLen))

	return min
}

// cmpInField compares a and b in a finite field of prime order, in which -1 is represented by
// minusOne.
func cmpInField(a, b, minusOne *big.Int) int {
	biggestPositiveNum := new(big.Int).Rsh(minusOne, 1)
	if a.Cmp(biggestPositiveNum)*b.Cmp(biggestPositiveNum) == -1 {
		return -a.Cmp(b)
	}
	return a.Cmp(b)
}

// minOutputHint produces the output of [BoundedComparator.Min] as a hint.
func minOutputHint(_ *big.Int, inputs, results []*big.Int) error {
	a := inputs[0]
	b := inputs[1]
	minusOne := inputs[2]

	if cmpInField(a, b, minusOne) == -1 {
		// a < b
		results[0].Set(a)
	} else {
		// a >= b
		results[0].Set(b)
	}
	return nil
}

// isLessOutputHint produces the output of [BoundedComparator.IsLess] as a hint.
func isLessOutputHint(_ *big.Int, inputs, results []*big.Int) error {
	a := inputs[0]
	b := inputs[1]
	minusOne := inputs[2]

	if cmpInField(a, b, minusOne) == -1 {
		// a < b
		results[0].SetUint64(1)
	} else {
		// a >= b
		results[0].SetUint64(0)
	}
	return nil
}
