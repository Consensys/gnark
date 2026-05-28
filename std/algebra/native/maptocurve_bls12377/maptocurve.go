package maptocurve_bls12377

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const (
	T = 256 // increment window size (8 bits)
	B = 1   // curve coefficient b for BLS12-377: y² = x³ + 1
	S = 46  // 2-adicity v₂(q-1) for BLS12-377 Fp
)

// YIncrement maps msg to a point (x, y) on y² = x³ + 1 using y-increment:
//
//	Y = msg·256 + k, Y² = X³ + 1
func YIncrement(api frontend.API, msg frontend.Variable) (x, y frontend.Variable, err error) {
	res, err := api.Compiler().NewHint(yIncrementHint, 2, msg)
	if err != nil {
		return nil, nil, err
	}
	k := res[0]
	x = res[1]

	y = api.Add(api.Mul(msg, T), k)

	// Y² = X³ + B
	lhs := api.Mul(y, y)
	rhs := api.Mul(x, x)
	rhs = api.Mul(rhs, x)
	rhs = api.Add(rhs, B)
	api.AssertIsEqual(lhs, rhs)

	// 0 ≤ K < 256
	rangecheck.New(api).Check(k, 8)

	return x, y, nil
}
