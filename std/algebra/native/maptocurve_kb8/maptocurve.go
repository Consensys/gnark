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

func assertIsOnCurve(api frontend.API, p *G1Affine) {
	isInf := api.And(p.X.IsZero(api), p.Y.IsZero(api))
	_, b := kb8.CurveCoefficients()
	left := *new(E8).Square(api, p.Y)
	x2 := *new(E8).Square(api, p.X)
	right := *new(E8).Mul(api, x2, p.X)
	right.Sub(api, right, *new(E8).MulByFp(api, p.X, 3))
	right.Add(api, right, newE8(b))
	diff := *new(E8).Sub(api, left, right)
	isCurve := diff.IsZero(api)
	api.AssertIsEqual(api.Or(isInf, isCurve), 1)
}

func IsCompatible(api frontend.API) bool {
	return api.Compiler().Field().Cmp(kbfp.Modulus()) == 0
}
