package sw_bls12381

import (
	"fmt"
	"math/big"
	"slices"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/hash/tofield"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	len_per_base_element = 64
)

func (g2 *G2) HashToG2(msg []uints.U8, dst []byte) (*G2Affine, error) {
	// Steps:
	// 1. u = hash_to_field(msg, 2)
	// 2. Q0 = map_to_curve(u[0])
	// 3. Q1 = map_to_curve(u[1])
	// 4. R = Q0 + Q1              # Point addition
	// 5. P = clear_cofactor(R)
	// 6. return P
	lenPerBaseElement := len_per_base_element
	lenInBytes := lenPerBaseElement * 4
	uniformBytes, e := tofield.ExpandMsgXmd(g2.api, msg, dst, lenInBytes)
	if e != nil {
		return &G2Affine{}, e
	}

	ele1 := bytesToElement(g2.api, g2.fp, uniformBytes[:lenPerBaseElement])
	ele2 := bytesToElement(g2.api, g2.fp, uniformBytes[lenPerBaseElement:lenPerBaseElement*2])
	ele3 := bytesToElement(g2.api, g2.fp, uniformBytes[lenPerBaseElement*2:lenPerBaseElement*3])
	ele4 := bytesToElement(g2.api, g2.fp, uniformBytes[lenPerBaseElement*3:])

	// we will still do iso_map before point addition, as we do not have point addition in E' (yet)
	Q0, err := g2.MapToCurve2(&fields_bls12381.E2{A0: *ele1, A1: *ele2})
	if err != nil {
		return nil, fmt.Errorf("map to curve Q1: %w", err)
	}
	Q1, err := g2.MapToCurve2(&fields_bls12381.E2{A0: *ele3, A1: *ele4})
	if err != nil {
		return nil, fmt.Errorf("map to curve Q2: %w", err)
	}
	Q0 = g2.isogeny(Q0)
	Q1 = g2.isogeny(Q1)

	R := g2.AddUnified(Q0, Q1)

	return g2.ClearCofactor(R), nil
}

func bytesToElement(api frontend.API, fp *emulated.Field[emulated.BLS12381Fp], data []uints.U8) *emulated.Element[emulated.BLS12381Fp] {
	// data in BE, need to convert to LE
	slices.Reverse(data)

	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		u8 := data[i]
		u8Bits := api.ToBinary(u8.Val, 8)
		for j := 0; j < 8; j++ {
			bits[i*8+j] = u8Bits[j]
		}
	}

	cutoff := 17
	tailBits, headBits := bits[:cutoff*8], bits[cutoff*8:]
	tail := fp.FromBits(tailBits...)
	head := fp.FromBits(headBits...)

	byteMultiplier := big.NewInt(256)
	headMultiplier := byteMultiplier.Exp(byteMultiplier, big.NewInt(int64(cutoff)), big.NewInt(0))
	head = fp.MulConst(head, headMultiplier)

	return fp.Add(head, tail)
}

func (g2 *G2) evalFixedPolynomial(monic bool, coefficients []bls12381.E2, x *fields_bls12381.E2) *fields_bls12381.E2 {
	emuCoefficients := make([]*fields_bls12381.E2, len(coefficients))
	for i := 0; i < len(coefficients); i++ {
		emuCoefficients[i] = &fields_bls12381.E2{
			A0: emulated.ValueOf[emparams.BLS12381Fp](coefficients[i].A0),
			A1: emulated.ValueOf[emparams.BLS12381Fp](coefficients[i].A1),
		}
	}
	var res *fields_bls12381.E2
	if monic {
		res = g2.Add(emuCoefficients[0], x)
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
	x0Bits := g2.fp.ToBitsCanonical(&x.A0)
	x1Bits := g2.fp.ToBitsCanonical(&x.A1)
	sign0 := x0Bits[0]
	zero0 := g2.api.IsZero(sign0)
	sign1 := x1Bits[0]
	tv := g2.api.And(zero0, sign1)
	s := g2.api.Or(sign0, tv)
	return s
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
	diff := g2.api.Sub(sgn0U, sgn0Y)
	e1 := g2.api.IsZero(diff)
	// 24.   y = CMOV(-y, y, e1)
	yNeg := g2.Ext2.Neg(y)
	y = g2.Ext2.Select(e1, y, yNeg)
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
