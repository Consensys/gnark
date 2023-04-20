package cmp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"math/big"
)

// IsLessUnsigned returns 1 if a < b, and returns 0 if a >= b. The comparison
// will be unsigned and all field elements will be treated as positive numbers.
// Therefore, If the underlying field is of prime order P, the elements will be
// considered to represent integers in range [0, P-1].
func IsLessUnsigned(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return isLessRecursive(api, bits.ToBinary(api, a), bits.ToBinary(api, b), false, true)
}

// IsLessOrEqualUnsigned returns 1 if a <= b, and returns 0 if a > b. The
// comparison will be unsigned and all field elements will be treated as
// positive numbers. Therefore, If the underlying field is of prime order P, the
// elements will be considered to represent integers in range [0, P-1].
func IsLessOrEqualUnsigned(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return isLessRecursive(api, bits.ToBinary(api, a), bits.ToBinary(api, b), true, true)
}

// IsLessBinary compares two binary numbers represented by aBits and bBits. It
// returns 1 if uint(aBits) < uint(bBits), and returns 0 if uint(aBits) >=
// uint(bBits). Here, we assume uint(aBits) returns the unsigned integer whose
// binary representation is aBits.
func IsLessBinary(api frontend.API, aBits, bBits []frontend.Variable) frontend.Variable {
	if len(aBits) != len(bBits) {
		panic("a and b must have the same length")
	}
	return isLessRecursive(api, aBits, bBits, false, true)
}

// IsLessOrEqualBinary compares two binary numbers represented by aBits and
// bBits. It returns 1 if uint(aBits) <= uint(bBits), and returns 0 if
// uint(aBits) > uint(bBits). Here, we assume uint(aBits) returns the unsigned
// integer whose binary representation is aBits.
func IsLessOrEqualBinary(api frontend.API, aBits, bBits []frontend.Variable) frontend.Variable {
	if len(aBits) != len(bBits) {
		panic("a and b must have the same length")
	}
	return isLessRecursive(api, aBits, bBits, true, true)
}

// isLessRecursive compares binary numbers a and b. When useBoundedCmp is false
// it performs normal bit by bit comparison which defines 2*n multiplication
// constraints. When useBoundedCmp is true, bit by bit comparison will be used
// for a few high order bits and the rest of bits will be compared by
// BoundedComparator. If addition is free, this will define n + 5 constraints
// when n == api.Compiler().FieldBitLen().
//
// acceptEquality determines the return value of the function when a == b.
func isLessRecursive(api frontend.API,
	a, b []frontend.Variable,
	acceptEquality bool, useBoundedCmp bool) frontend.Variable {
	n := len(a)
	if n == 0 {
		if acceptEquality {
			return 1
		} else {
			return 0
		}
	}
	// Interestingly when one of the two numbers is a constant, using bit by bit
	// comparison will produce 3 fewer constraints than using the BoundedComparator.
	if useBoundedCmp && n <= api.Compiler().FieldBitLen()-2 &&
		isNotConstant(api, a[n-1]) && isNotConstant(api, b[n-1]) {
		diffBound := new(big.Int).Lsh(big.NewInt(1), uint(n))
		diffBound.Sub(diffBound, big.NewInt(1))
		comparator := NewBoundedComparator(api, diffBound, false)
		a := bits.FromBinary(api, a, bits.WithUnconstrainedInputs())
		b := bits.FromBinary(api, b, bits.WithUnconstrainedInputs())
		if acceptEquality {
			return comparator.IsLessEq(a, b)
		} else {
			return comparator.IsLess(a, b)
		}
	}

	// out = (a[n-1] + b[n-1] - 2*a[n-1]*b[n-1])*(b[n-1] - cmp) + cmp
	eq := api.Add(a[n-1], b[n-1], api.Mul(-2, a[n-1], b[n-1]))
	cmp := isLessRecursive(api, a[:n-1], b[:n-1], acceptEquality, useBoundedCmp)
	return api.Add(cmp, api.Mul(eq, api.Sub(b[n-1], cmp)))
}

func isNotConstant(api frontend.API, x frontend.Variable) bool {
	_, isConstant := api.Compiler().ConstantValue(x)
	return !isConstant
}
