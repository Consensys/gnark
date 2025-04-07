package sw_bls12381

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type FpApi = emulated.Field[emulated.BLS12381Fp]

func g1EvalFixedPolynomial(api *FpApi, monic bool, coefficients []fp.Element, x *baseEl) (*baseEl, error) {
	emuCoefficients := make([]*baseEl, len(coefficients))
	for i := range coefficients {
		emulatedCoefficient := emulated.ValueOf[emulated.BLS12381Fp](coefficients[i])
		emuCoefficients[i] = &emulatedCoefficient
	}
	var res *baseEl
	if monic {
		res = api.Add(emuCoefficients[len(emuCoefficients)-1], x)
	} else {
		res = emuCoefficients[len(emuCoefficients)-1]
	}

	for i := len(emuCoefficients) - 2; i >= 0; i-- {
		res = api.Mul(res, x)
		res = api.Add(res, emuCoefficients[i])
	}
	return res, nil

}

func g1Isogeny(fpApi *FpApi, p *G1Affine) (*G1Affine, error) {
	isogenyMap := hash_to_curve.G1IsogenyMap()
	ydenom, err := g1EvalFixedPolynomial(fpApi, true, isogenyMap[3], &p.X)
	if err != nil {
		return nil, fmt.Errorf("y denom: %w", err)
	}
	xdenom, err := g1EvalFixedPolynomial(fpApi, true, isogenyMap[1], &p.X)
	if err != nil {
		return nil, fmt.Errorf("x denom: %w", err)
	}
	y, err := g1EvalFixedPolynomial(fpApi, false, isogenyMap[2], &p.X)
	if err != nil {
		return nil, fmt.Errorf("y num: %w", err)
	}
	y = fpApi.Mul(y, &p.Y)
	x, err := g1EvalFixedPolynomial(fpApi, false, isogenyMap[0], &p.X)
	if err != nil {
		return nil, fmt.Errorf("x num: %w", err)
	}
	x = fpApi.Div(x, xdenom)
	y = fpApi.Div(y, ydenom)
	return &G1Affine{X: *x, Y: *y}, nil
}

// g1Sgn0 returns the parity of a
func g1Sgn0(api *FpApi, a *baseEl) frontend.Variable {
	aReduced := api.Reduce(a)
	ab := api.ToBits(aReduced)
	return ab[0]
}

func ClearCofactor(g *G1, q *G1Affine) (*G1Affine, error) {

	// cf https://eprint.iacr.org/2019/403.pdf, 5

	// mulBySeed
	z := g.double(q)
	z = g.add(z, q)
	z = g.double(z)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 2)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 8)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 31)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 16)

	// Add assign
	z = g.add(z, q)

	return z, nil

}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-simplified-swu-method
// MapToCurve1 implements the SSWU map
// No cofactor clearing or isogeny
func MapToCurve1(api frontend.API, u *baseEl) (*G1Affine, error) {
	one := emulated.ValueOf[emulated.BLS12381Fp]("1")
	eleven := emulated.ValueOf[emulated.BLS12381Fp]("11")

	fpApi, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, err
	}

	sswuIsoCurveCoeffA := emulated.ValueOf[emulated.BLS12381Fp]("0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d")
	sswuIsoCurveCoeffB := emulated.ValueOf[emulated.BLS12381Fp]("0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0")

	tv1 := fpApi.Mul(u, u) // 1.  tv1 = u²

	//mul tv1 by Z ( g1MulByZ)
	tv1 = fpApi.Mul(&eleven, tv1)

	// var tv2 fp.Element
	tv2 := fpApi.Mul(tv1, tv1) // 3.  tv2 = tv1²
	tv2 = fpApi.Add(tv2, tv1)  // 4.  tv2 = tv2 + tv1

	// var tv3 fp.Element
	// var tv4 fp.Element
	tv3 := fpApi.Add(tv2, &one)               // 5.  tv3 = tv2 + 1
	tv3 = fpApi.Mul(tv3, &sswuIsoCurveCoeffB) // 6.  tv3 = B * tv3

	// tv2NZero := g1NotZero(&tv2)
	tv2IsZero := fpApi.IsZero(tv2)

	// tv4 = Z

	tv2 = fpApi.Neg(tv2)                         // tv2.Neg(&tv2)
	tv4 := fpApi.Select(tv2IsZero, &eleven, tv2) // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 = fpApi.Mul(tv4, &sswuIsoCurveCoeffA)    // 8.  tv4 = A * tv4

	tv2 = fpApi.Mul(tv3, tv3) // 9.  tv2 = tv3²

	tv6 := fpApi.Mul(tv4, tv4) // 10. tv6 = tv4²

	tv5 := fpApi.Mul(tv6, &sswuIsoCurveCoeffA) // 11. tv5 = A * tv6

	tv2 = fpApi.Add(tv2, tv5) // 12. tv2 = tv2 + tv5
	tv2 = fpApi.Mul(tv2, tv3) // 13. tv2 = tv2 * tv3
	tv6 = fpApi.Mul(tv6, tv4) // 14. tv6 = tv6 * tv4

	tv5 = fpApi.Mul(tv6, &sswuIsoCurveCoeffB) // 15. tv5 = B * tv6
	tv2 = fpApi.Add(tv2, tv5)                 // 16. tv2 = tv2 + tv5

	x := fpApi.Mul(tv1, tv3) // 17.   x = tv1 * tv3

	hint, err := fpApi.NewHint(g1SqrtRatioHint, 2, tv2, tv6)
	if err != nil {
		return nil, err
	}

	y1 := hint[0] // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

	// TODO constrain gx1NSquare and y1
	// (gx1NSquare==1 AND (u/v) QNR ) OR (gx1NSquare==0 AND (u/v) QR )
	gx1NSquare := hint[1].Limbs[0]

	api.AssertIsBoolean(gx1NSquare)
	y1Squarev := fpApi.Mul(y1, y1)
	y1Squarev = fpApi.Mul(y1Squarev, tv6)
	uz := fpApi.Mul(tv2, &eleven)
	ysvMinusuz := fpApi.Sub(y1Squarev, uz)
	isQNRWitness := fpApi.IsZero(ysvMinusuz)
	cond1 := api.And(isQNRWitness, gx1NSquare)

	ysvMinusu := fpApi.Sub(y1Squarev, tv2)
	isQRWitness := fpApi.IsZero(ysvMinusu)
	isQR := api.Sub(1, gx1NSquare)
	cond2 := api.And(isQR, isQRWitness)

	cond := api.Xor(cond1, cond2)
	api.AssertIsEqual(cond, 1)

	// var y fp.Element
	y := fpApi.Mul(tv1, u) // 19.  	 y = tv1 * u

	y = fpApi.Mul(y, y1) // 20.   y = y * y1

	x = fpApi.Select(gx1NSquare, x, tv3) // 21.   x = CMOV(x, tv3, is_gx1_square)
	y = fpApi.Select(gx1NSquare, y, y1)  // 22.   y = CMOV(y, y1, is_gx1_square)

	y1 = fpApi.Neg(y)
	y1 = fpApi.Reduce(y1)
	sel := api.IsZero(api.Sub(g1Sgn0(fpApi, u), g1Sgn0(fpApi, y)))
	y = fpApi.Select(sel, y, y1)

	// // 23.  e1 = sgn0(u) == sgn0(y)
	// // 24.   y = CMOV(-y, y, e1)

	x = fpApi.Div(x, tv4) // 25.   x = x / tv4

	return &G1Affine{X: *x, Y: *y}, nil

}

// MapToG1 invokes the SSWU map, and guarantees that the result is in g1
func MapToG1(api frontend.API, u *baseEl) (*G1Affine, error) {

	res, err := MapToCurve1(api, u)
	if err != nil {
		return nil, err
	}

	//this is in an isogenous curve
	fpApi, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, err
	}
	z, err := g1Isogeny(fpApi, res)
	if err != nil {
		return nil, err
	}

	g1, err := NewG1(api)
	if err != nil {
		return nil, err
	}

	z, err = ClearCofactor(g1, z)
	if err != nil {
		return nil, err
	}

	return z, nil
}
