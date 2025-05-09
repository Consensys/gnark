package sw_bls12381

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
)

func (g1 *G1) evalFixedPolynomial(monic bool, coefficients []fp.Element, x *baseEl) *baseEl {
	emuCoefficients := make([]*baseEl, len(coefficients))
	for i := range coefficients {
		emulatedCoefficient := *g1.curveF.NewElement(coefficients[i])
		emuCoefficients[i] = &emulatedCoefficient
	}
	var res *baseEl
	if monic {
		res = g1.curveF.Add(emuCoefficients[len(emuCoefficients)-1], x)
	} else {
		res = emuCoefficients[len(emuCoefficients)-1]
	}

	for i := len(emuCoefficients) - 2; i >= 0; i-- {
		res = g1.curveF.Mul(res, x)
		res = g1.curveF.Add(res, emuCoefficients[i])
	}
	return res

}

func (g1 *G1) isogeny(p *G1Affine) *G1Affine {
	isogenyMap := hash_to_curve.G1IsogenyMap()
	ydenom := g1.evalFixedPolynomial(true, isogenyMap[3], &p.X)
	xdenom := g1.evalFixedPolynomial(true, isogenyMap[1], &p.X)
	y := g1.evalFixedPolynomial(false, isogenyMap[2], &p.X)
	y = g1.curveF.Mul(y, &p.Y)
	x := g1.evalFixedPolynomial(false, isogenyMap[0], &p.X)
	x = g1.curveF.Div(x, xdenom)
	y = g1.curveF.Div(y, ydenom)
	return &G1Affine{X: *x, Y: *y}
}

// g1Sgn0 returns the parity of a
func (g1 *G1) sgn0(a *baseEl) frontend.Variable {
	ab := g1.curveF.ToBitsCanonical(a)
	return ab[0]
}

// ClearCofactor clears the cofactor of a point in G1.
//
// See: https://eprint.iacr.org/2019/403.pdf, 5
func (g1 *G1) ClearCofactor(q *G1Affine) *G1Affine {
	// cf https://eprint.iacr.org/2019/403.pdf, 5

	// mulBySeed
	z := g1.double(q)
	z = g1.add(z, q)
	z = g1.double(z)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 2)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 8)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 31)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 16)

	// Add assign
	z = g1.add(z, q)

	return z
}

// MapToCurve1 implements the SSWU map. It does not perform cofactor clearing or isogeny computation.
// See [G1.MapToG1] for the complete map to G1.
//
// See: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-simplified-swu-method
func (g1 *G1) MapToCurve1(u *baseEl) (*G1Affine, error) {
	one := g1.curveF.One()
	z := g1.curveF.NewElement(hash_to_curve.G1SSWUIsogenyZ())

	sswuIsoCurveCoeffAValue, sswuIsoCurveCoeffBValue := hash_to_curve.G1SSWUIsogenyCurveCoefficients()
	sswuIsoCurveCoeffA := g1.curveF.NewElement(sswuIsoCurveCoeffAValue)
	sswuIsoCurveCoeffB := g1.curveF.NewElement(sswuIsoCurveCoeffBValue)

	tv1 := g1.curveF.Mul(u, u) // 1.  tv1 = u²

	//mul tv1 by Z ( g1MulByZ)
	tv1 = g1.curveF.Mul(z, tv1)

	// var tv2 fp.Element
	tv2 := g1.curveF.Mul(tv1, tv1) // 3.  tv2 = tv1²
	tv2 = g1.curveF.Add(tv2, tv1)  // 4.  tv2 = tv2 + tv1

	// var tv3 fp.Element
	// var tv4 fp.Element
	tv3 := g1.curveF.Add(tv2, one)               // 5.  tv3 = tv2 + 1
	tv3 = g1.curveF.Mul(tv3, sswuIsoCurveCoeffB) // 6.  tv3 = B * tv3

	// tv2NZero := g1NotZero(&tv2)
	tv2IsZero := g1.curveF.IsZero(tv2)

	// tv4 = Z

	tv2 = g1.curveF.Neg(tv2)                     // tv2.Neg(&tv2)
	tv4 := g1.curveF.Select(tv2IsZero, z, tv2)   // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 = g1.curveF.Mul(tv4, sswuIsoCurveCoeffA) // 8.  tv4 = A * tv4

	tv2 = g1.curveF.Mul(tv3, tv3) // 9.  tv2 = tv3²

	tv6 := g1.curveF.Mul(tv4, tv4) // 10. tv6 = tv4²

	tv5 := g1.curveF.Mul(tv6, sswuIsoCurveCoeffA) // 11. tv5 = A * tv6

	tv2 = g1.curveF.Add(tv2, tv5) // 12. tv2 = tv2 + tv5
	tv2 = g1.curveF.Mul(tv2, tv3) // 13. tv2 = tv2 * tv3
	tv6 = g1.curveF.Mul(tv6, tv4) // 14. tv6 = tv6 * tv4

	tv5 = g1.curveF.Mul(tv6, sswuIsoCurveCoeffB) // 15. tv5 = B * tv6
	tv2 = g1.curveF.Add(tv2, tv5)                // 16. tv2 = tv2 + tv5

	x := g1.curveF.Mul(tv1, tv3) // 17.   x = tv1 * tv3

	hint, err := g1.curveF.NewHint(g1SqrtRatioHint, 2, tv2, tv6)
	if err != nil {
		return nil, err
	}

	y1 := hint[0] // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

	// (gx1NSquare==1 AND (u/v) QNR ) OR (gx1NSquare==0 AND (u/v) QR )
	gx1NSquare := hint[1].Limbs[0]

	g1.api.AssertIsBoolean(gx1NSquare)
	y1Squarev := g1.curveF.Mul(y1, y1)
	y1Squarev = g1.curveF.Mul(y1Squarev, tv6)
	uz := g1.curveF.Mul(tv2, z)
	ysvMinusuz := g1.curveF.Sub(y1Squarev, uz)
	isQNRWitness := g1.curveF.IsZero(ysvMinusuz)
	cond1 := g1.api.And(isQNRWitness, gx1NSquare)

	ysvMinusu := g1.curveF.Sub(y1Squarev, tv2)
	isQRWitness := g1.curveF.IsZero(ysvMinusu)
	isQR := g1.api.Sub(1, gx1NSquare)
	cond2 := g1.api.And(isQR, isQRWitness)

	cond := g1.api.Xor(cond1, cond2)
	g1.api.AssertIsEqual(cond, 1)

	// var y fp.Element
	y := g1.curveF.Mul(tv1, u) // 19.  	 y = tv1 * u

	y = g1.curveF.Mul(y, y1) // 20.   y = y * y1

	x = g1.curveF.Select(gx1NSquare, x, tv3) // 21.   x = CMOV(x, tv3, is_gx1_square)
	y = g1.curveF.Select(gx1NSquare, y, y1)  // 22.   y = CMOV(y, y1, is_gx1_square)

	y1 = g1.curveF.Neg(y)
	y1 = g1.curveF.Reduce(y1)
	sel := g1.api.IsZero(g1.api.Sub(g1.sgn0(u), g1.sgn0(y)))
	y = g1.curveF.Select(sel, y, y1)

	// // 23.  e1 = sgn0(u) == sgn0(y)
	// // 24.   y = CMOV(-y, y, e1)

	x = g1.curveF.Div(x, tv4) // 25.   x = x / tv4

	return &G1Affine{X: *x, Y: *y}, nil

}

// MapToG1 invokes the SSWU map, and guarantees that the result is in G1. For
// variant without cofactor clearing and isogeny, see [G1.MapToCurve1].
func (g1 *G1) MapToG1(u *baseEl) (*G1Affine, error) {
	res, err := g1.MapToCurve1(u)
	if err != nil {
		return nil, fmt.Errorf("map to curve: %w", err)
	}
	z := g1.isogeny(res)
	z = g1.ClearCofactor(z)
	return z, nil
}
