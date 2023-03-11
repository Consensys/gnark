package cmp

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
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
// known. These methods perform only one binary conversion of length: absDiffUppBitLen. See
// NewComparator, for more information.
type BoundedComparator struct {
	// Let's denote the upper bound of the absolute difference of a and b, with ADU, such that we have
	// |a - b| <= ADU. The absDiffUppBitLen must be the number of bits of the binary representation of
	// ADU. In other words, the value of absDiffUppBitLen should be chosen in a way that we always have
	// |a - b| <= 2^absDiffUppBitLen - 1.
	absDiffUppBitLen int
	api              frontend.API

	// we will use value receiver for methods of this struct,
	// since: 1) the struct is small. 2) methods should not modify any fields.
}

// NewComparator creates a new BoundedComparator, which provides methods for comparing two numbers a
// and b.
//
// absDiffUpp is the upper bound of the absolute difference of a and b, such that |a - b| <=
// absDiffUpp. absDiffUpp must be a positive number, and P - absDiffUpp must have a longer binary
// representation than absDiffUpp, where P is the order of the underlying field. Lower values of
// absDiffUpp will reduce the number of generated constraints.
//
// This function panics when the provided value for absDiffUpp is not valid.
//
// As long as |a - b| < 2^absDiffUpp.BitLen(), all the methods of BoundedComparator work correctly.
// If |a - b| = 2^absDiffUpp.BitLen(), either a proof can not be generated or the methods work
// correctly. If |a - b| > 2^absDiffUpp.BitLen(), as long as |a - b| < 2^floor(log(P - |a - b|)), no
// proofs can be generated.
//
// When |a - b| >= 2^floor(log(P - |a - b|)), the behaviour of the exported methods of
// BoundedComparator is undefined.
func NewComparator(api frontend.API, absDiffUpp *big.Int) *BoundedComparator {
	// We need to make sure that always P - |a - b| has a longer binary representation than |a - b|.
	// These two numbers get closer as |a - b| increases, so we just need to check that P - absDiffUpp
	// has a longer binary representation than absDiffUpp.
	P := api.Compiler().Field()
	if absDiffUpp.Cmp(big.NewInt(0)) != 1 || absDiffUpp.Cmp(P) != -1 {
		panic("absDiffUpp must be a positive number smaller than the field order")
	}
	bitLenOfNeg := new(big.Int).Sub(P, absDiffUpp).BitLen()
	bitLenOfPos := absDiffUpp.BitLen()
	if bitLenOfNeg <= bitLenOfPos {
		panic("cannot construct the comparator, the specified absDiffUpp is too high")
	}
	return &BoundedComparator{
		absDiffUppBitLen: bitLenOfPos,
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
