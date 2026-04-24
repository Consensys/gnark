package maptocurve_grumpkin

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const (
	T = 256 // increment window size (8 bits)
	B = -17 // curve coefficient b for Grumpkin: y² = x³ - 17
)

// YIncrement maps msg to a point (x, y) on y² = x³ - 17 using y-increment:
//
//	Y = msg·256 + k, Y² = X³ - 17
func YIncrement(api frontend.API, msg frontend.Variable) (x, y frontend.Variable, err error) {
	// hint outputs: [k, x]
	res, err := api.Compiler().NewHint(yIncrementHint, 2, msg)
	if err != nil {
		return nil, nil, err
	}
	k := res[0]
	x = res[1]

	// Reconstruct Y = msg*T + K
	y = api.Add(api.Mul(msg, T), k)

	// (1) Y² = X³ + B
	lhs := api.Mul(y, y)
	rhs := api.Mul(x, x)
	rhs = api.Mul(rhs, x)
	rhs = api.Add(rhs, B)
	api.AssertIsEqual(lhs, rhs)

	// (2) 0 ≤ K < 256
	rangecheck.New(api).Check(k, 8)

	return x, y, nil
}
