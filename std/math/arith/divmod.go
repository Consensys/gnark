package arith

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// DivMod returns quotient = x / y and modulus = x % y
// If y == 0, a division-by-zero run-time panic occurs.
//
// DivMod implements Euclidean division and modulus:
//
//	q = x div y  such that
//	m = x - y*q  with 0 <= m < y
//
// The method enforces that modulus < y, and quotient*y + modulus == x.
func DivMod(api frontend.API, x frontend.Variable, y uint) (quotient, modulus frontend.Variable) {
	if y == 1 {
		return x, 0
	}

	div := big.NewInt(int64(y))

	// handle constant case
	if xc, ok := api.Compiler().ConstantValue(x); ok {
		q, m := new(big.Int), new(big.Int)
		q.DivMod(xc, div, m)
		return q, m
	}

	ret, err := api.Compiler().NewHint(divmodHint, 2, x, y)
	if err != nil {
		panic(err)
	}

	quotient = ret[0]
	modulus = ret[1]

	cmp.NewBoundedComparator(api, div, false).AssertIsLess(modulus, y)
	composed := api.Add(modulus, api.Mul(quotient, div))
	api.AssertIsEqual(composed, x)
	return
}
