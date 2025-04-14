package sw_bls12381

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
)

func (g2 *G2) evalFixedPolynomial(monic bool, coefficients []bls12381.E2, x *fields_bls12381.E2) *fields_bls12381.E2 {
	emuCoefficients := make([]*fields_bls12381.E2, len(coefficients))
	for i := 0; i < len(coefficients); i++ {
		emuCoefficients[i] = &fields_bls12381.E2{
			A0: *g2.fp.NewElement(coefficients[i].A0),
			A1: *g2.fp.NewElement(coefficients[i].A1),
		}
	}
	var res *fields_bls12381.E2
	if monic {
		res = g2.Add(emuCoefficients[len(emuCoefficients)-1], x)
	} else {
		res = emuCoefficients[len(emuCoefficients)-1]
	}

	for i := len(emuCoefficients) - 2; i >= 0; i-- {
		res = g2.Mul(res, x)
		res = g2.Add(res, emuCoefficients[i])
	}

	return res
}

func (g2 *G2) isogeny(p *G2Affine) *G2Affine {
	isogenyMap := hash_to_curve.G2IsogenyMap()
	ydenom := g2.evalFixedPolynomial(true, isogenyMap[3], &p.P.X)
	xdenom := g2.evalFixedPolynomial(true, isogenyMap[1], &p.P.X)
	y := g2.evalFixedPolynomial(false, isogenyMap[2], &p.P.X)
	y = g2.Mul(y, &p.P.Y)
	x := g2.evalFixedPolynomial(false, isogenyMap[0], &p.P.X)
	x = g2.DivUnchecked(x, xdenom)
	y = g2.DivUnchecked(y, ydenom)
	return &G2Affine{P: g2AffP{X: *x, Y: *y}}
}

func (g2 *G2) sgn0(x *fields_bls12381.E2) frontend.Variable {
	// https://www.rfc-editor.org/rfc/rfc9380.html#name-the-sgn0-function case m=2
	x0Bits := g2.fp.ToBitsCanonical(&x.A0)
	x1Bits := g2.fp.ToBitsCanonical(&x.A1)

	sign0 := x0Bits[0]                                 // 1. sign_0 = x_0 mod 2
	zero0 := g2.fp.IsZero(&x.A0)                       // 2. zero_0 = x_0 == 0
	sign1 := x1Bits[0]                                 // 3. sign_1 = x_1 mod 2
	sign := g2.api.Or(sign0, g2.api.And(zero0, sign1)) // 4. s = sign_0 OR (zero_0 AND sign_1)
	return sign
}

// sqrtRatio computes u/v and returns (isQR, y) where isQR indicates if the
// result is a quadratic residue.
func (g2 *G2) sqrtRatio(u, v *fields_bls12381.E2) (frontend.Variable, *fields_bls12381.E2, error) {
	// Steps
	// 1. extract the base values of u, v, then compute G2SqrtRatio with gnark-crypto
	x, err := g2.fp.NewHint(g2SqrtRatioHint, 3, &u.A0, &u.A1, &v.A0, &v.A1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate sqrtRatio with gnark-crypto: %w", err)
	}

	b := g2.fp.IsZero(x[0])
	y := fields_bls12381.E2{A0: *x[1], A1: *x[2]}

	// 2. apply constraints
	// b1 := {b = True AND y^2 * v = u}
	g2.api.AssertIsBoolean(b)
	y2 := g2.Ext2.Square(&y)
	y2v := g2.Ext2.Mul(y2, v)
	bY2vu := g2.Ext2.IsZero(g2.Ext2.Sub(y2v, u))
	b1 := g2.api.And(b, bY2vu)

	// b2 := {b = False AND y^2 * v = Z * u}
	uZ := g2.Ext2.Mul(g2.sswuZ, u)
	bY2vZu := g2.Ext2.IsZero(g2.Ext2.Sub(y2v, uZ))
	nb := g2.api.IsZero(b)
	b2 := g2.api.And(nb, bY2vZu)

	cmp := g2.api.Or(b1, b2)
	g2.api.AssertIsEqual(cmp, 1)

	return b, &y, nil
}

// ClearCofactor clears the cofactor of the point p in G2.
//
// See https://www.rfc-editor.org/rfc/rfc9380.html#name-cofactor-clearing-for-bls12
func (g2 *G2) ClearCofactor(p *G2Affine) *G2Affine {
	// Steps:
	// 1.  t1 = c1 * P
	// c1 = -15132376222941642752
	t1 := g2.scalarMulBySeed(p)
	// 2.  t2 = psi(P)
	t2 := g2.psi(p)
	// 3.  t3 = 2 * P
	t3 := g2.double(p)
	// 4.  t3 = psi2(t3)
	t3 = g2.psi2(t3)
	// 5.  t3 = t3 - t2
	t3 = g2.sub(t3, t2)
	// 6.  t2 = t1 + t2
	t2 = g2.AddUnified(t1, t2)
	// 7.  t2 = c1 * t2
	t2 = g2.scalarMulBySeed(t2)
	// 8.  t3 = t3 + t2
	t3 = g2.AddUnified(t3, t2)
	// 9.  t3 = t3 - t1
	t3 = g2.sub(t3, t1)
	// 10.  Q = t3 - P
	Q := g2.sub(t3, p)
	// 11. return Q
	return Q
}

func (g2 *G2) MapToCurve2(u *fields_bls12381.E2) (*G2Affine, error) {
	// SSWU Steps:
	// 1.  tv1 = u^2
	tv1 := g2.Ext2.Square(u)
	// 2.  tv1 = Z * tv1
	tv1 = g2.Ext2.Mul(g2.sswuZ, tv1)
	// 3.  tv2 = tv1^2
	tv2 := g2.Ext2.Square(tv1)
	// 4.  tv2 = tv2 + tv1
	tv2 = g2.Ext2.Add(tv2, tv1)
	// 5.  tv3 = tv2 + 1
	tv3 := g2.Ext2.Add(tv2, g2.Ext2.One())
	// 6.  tv3 = B * tv3
	tv3 = g2.Ext2.Mul(g2.sswuCoeffB, tv3)
	// 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	s1 := g2.Ext2.IsZero(tv2)
	tv4 := g2.Ext2.Select(s1, g2.sswuZ, g2.Ext2.Neg(tv2))
	// 8.  tv4 = A * tv4
	tv4 = g2.Ext2.Mul(g2.sswuCoeffA, tv4)
	// 9.  tv2 = tv3^2
	tv2 = g2.Ext2.Square(tv3)
	// 10. tv6 = tv4^2
	tv6 := g2.Ext2.Square(tv4)
	// 11. tv5 = A * tv6
	tv5 := g2.Ext2.Mul(g2.sswuCoeffA, tv6)
	// 12. tv2 = tv2 + tv5
	tv2 = g2.Ext2.Add(tv2, tv5)
	// 13. tv2 = tv2 * tv3
	tv2 = g2.Ext2.Mul(tv2, tv3)
	// 14. tv6 = tv6 * tv4
	tv6 = g2.Ext2.Mul(tv6, tv4)
	// 15. tv5 = B * tv6
	tv5 = g2.Ext2.Mul(g2.sswuCoeffB, tv6)
	// 16. tv2 = tv2 + tv5
	tv2 = g2.Ext2.Add(tv2, tv5)
	// 17.   x = tv1 * tv3
	x := g2.Ext2.Mul(tv1, tv3)
	// 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	isGx1Square, y1, err := g2.sqrtRatio(tv2, tv6)
	if err != nil {
		return nil, fmt.Errorf("square ratio: %w", err)
	}
	// 19.   y = tv1 * u
	y := g2.Ext2.Mul(tv1, u)
	// 20.   y = y * y1
	y = g2.Ext2.Mul(y, y1)
	// 21.   x = CMOV(x, tv3, is_gx1_square)
	x = g2.Ext2.Select(isGx1Square, tv3, x)
	// 22.   y = CMOV(y, y1, is_gx1_square)
	y = g2.Ext2.Select(isGx1Square, y1, y)
	// 23.  e1 = sgn0(u) == sgn0(y)
	sgn0U := g2.sgn0(u)
	sgn0Y := g2.sgn0(y)
	e1 := g2.api.Xor(sgn0U, sgn0Y) // we keep in mind that e1 = 1-(sgn0U == sgn0Y) as in gnark-crypto
	// 24.   y = CMOV(-y, y, e1)
	yNeg := g2.Ext2.Neg(y)
	y = g2.Ext2.Select(e1, yNeg, y) // contrary to gnark-crypto, if e1=1 we select yNeg and y otherwise
	// 25.   x = x / tv4
	x = g2.Ext2.DivUnchecked(x, tv4)
	// 26. return (x, y)
	return &G2Affine{
		P: g2AffP{X: *x, Y: *y},
	}, nil
}

func (g2 *G2) MapToG2(u *fields_bls12381.E2) (*G2Affine, error) {
	res, err := g2.MapToCurve2(u)
	if err != nil {
		return nil, fmt.Errorf("map to curve: %w", err)
	}
	z := g2.isogeny(res)
	z = g2.ClearCofactor(z)
	return z, nil
}
