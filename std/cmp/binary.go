package cmp

import (
	"github.com/consensys/gnark/frontend"
)

// BinaryIsLess TODO: determine the relation of this function with BoundedComparator methods
func BinaryIsLess(api frontend.API, aBits, bBits []frontend.Variable) frontend.Variable {
	if len(aBits) != len(bBits) {
		panic("a and b must have the same length")
	}
	return isLessRecursive(api, aBits, bBits, false)
}

// BinaryIsLessEq is ...
func BinaryIsLessEq(api frontend.API, aBits, bBits []frontend.Variable) frontend.Variable {
	if len(aBits) != len(bBits) {
		panic("a and b must have the same length")
	}
	return isLessRecursive(api, aBits, bBits, true)
}

func isLessRecursive(api frontend.API, a, b []frontend.Variable, acceptEquality bool) frontend.Variable {
	n := len(a)
	if n == 0 {
		if acceptEquality {
			return 1
		} else {
			return 0
		}
	}
	// out = (a[n-1] + b[n-1] - 2*a[n-1]*b[n-1])*(b[n-1] - cmp) + cmp
	eq := api.Add(a[n-1], b[n-1], api.Mul(-2, a[n-1], b[n-1]))
	cmp := isLessRecursive(api, a[:n-1], b[:n-1], acceptEquality)
	return api.Add(cmp, api.Mul(eq, api.Sub(b[n-1], cmp)))
}
