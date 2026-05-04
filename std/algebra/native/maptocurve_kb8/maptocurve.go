package maptocurve_kb8

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/kb8"
	kbfp "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_kb8"
	"github.com/consensys/gnark/std/rangecheck"
)

const T = 256

// YIncrement maps msg to a point on kb8 with y = msg*256 + k.
func YIncrement(api frontend.API, msg frontend.Variable) (G1Affine, error) {
	if !IsCompatible(api) {
		return G1Affine{}, errors.New("expected KoalaBear native field for kb8 map-to-curve")
	}
	_ = api.ToBinary(msg, 16)

	res, err := api.Compiler().NewHint(yIncrementHint, 9, msg)
	if err != nil {
		return G1Affine{}, err
	}
	k := res[0]
	rangecheck.New(api).Check(k, 8)

	x := fromCoeffs(res[1:])
	var y fields_kb8.E8
	y0 := api.Add(api.Mul(msg, T), k)
	y.SetZero()
	y.C0.B0.A0 = y0
	p := G1Affine{X: x, Y: y}

	assertIsOnCurve(api, &p)
	return p, nil
}

// assertIsOnCurve asserts y² = x³ - 3x + b for a point from the y-increment map.
//
// Optimizations over a generic on-curve check:
//   - y is in the base subfield (y = (y0,0,...,0)), so y² = (y0²,0,...,0) costs
//     1 Fp mul instead of a full E8.Square (72 gates).
//   - The map never produces infinity, so the isInf branch is removed (~30 gates).
//   - The result is checked via direct AssertIsEqual instead of IsZero+Or (~15 gates).
func assertIsOnCurve(api frontend.API, p *G1Affine) {
	_, b := kb8.CurveCoefficients()

	// y² — exploit that y is in the base subfield: only y.C0.B0.A0 is nonzero
	var ySquared E8
	ySquared.SetZero()
	ySquared.C0.B0.A0 = api.Mul(p.Y.C0.B0.A0, p.Y.C0.B0.A0)

	// x³ - 3x + b
	x2 := *new(E8).Square(api, p.X)
	rhs := *new(E8).Mul(api, x2, p.X)
	rhs.Sub(api, rhs, *new(E8).MulByFp(api, p.X, 3))
	rhs.Add(api, rhs, newE8(b))

	ySquared.AssertIsEqual(api, rhs)
}

func IsCompatible(api frontend.API) bool {
	return api.Compiler().Field().Cmp(kbfp.Modulus()) == 0
}
