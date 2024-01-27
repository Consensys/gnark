package sw_bls12381

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/hash/tofield"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	security_level       = 128
	len_per_base_element = 64
)

func HashToG2(api frontend.API, msg []uints.U8, dst []byte) (*G2Affine, error) {
	fp, e := emulated.NewField[emulated.BLS12381Fp](api)
	if e != nil {
		return &G2Affine{}, e
	}
	ext2 := fields_bls12381.NewExt2(api)
	mapper := newMapper(api, ext2, fp)
	g2 := NewG2(api)

	// Steps:
	// 1. u = hash_to_field(msg, 2)
	// 2. Q0 = map_to_curve(u[0])
	// 3. Q1 = map_to_curve(u[1])
	// 4. R = Q0 + Q1              # Point addition
	// 5. P = clear_cofactor(R)
	// 6. return P
	lenPerBaseElement := len_per_base_element
	lenInBytes := lenPerBaseElement * 4
	uniformBytes, e := tofield.ExpandMsgXmd(api, msg, dst, lenInBytes)
	if e != nil {
		return &G2Affine{}, e
	}

	ele1 := bytesToElement(api, fp, uniformBytes[:lenPerBaseElement])
	ele2 := bytesToElement(api, fp, uniformBytes[lenPerBaseElement:lenPerBaseElement*2])
	ele3 := bytesToElement(api, fp, uniformBytes[lenPerBaseElement*2:lenPerBaseElement*3])
	ele4 := bytesToElement(api, fp, uniformBytes[lenPerBaseElement*3:])

	// we will still do iso_map before point addition, as we do not have point addition in E' (yet)
	Q0 := mapper.mapToCurve(fields_bls12381.E2{A0: *ele1, A1: *ele2})
	Q1 := mapper.mapToCurve(fields_bls12381.E2{A0: *ele3, A1: *ele4})
	Q0 = mapper.isogeny(&Q0.P.X, &Q0.P.Y)
	Q1 = mapper.isogeny(&Q1.P.X, &Q1.P.Y)

	R := g2.addUnified(Q0, Q1)

	return clearCofactor(g2, fp, R), nil
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

type sswuMapper struct {
	A, B, Z fields_bls12381.E2
	ext2    *fields_bls12381.Ext2
	fp      *emulated.Field[emulated.BLS12381Fp]
	api     frontend.API
	iso     *isogeny
}

func newMapper(api frontend.API, ext2 *fields_bls12381.Ext2, fp *emulated.Field[emulated.BLS12381Fp]) *sswuMapper {
	coeff_a := fields_bls12381.E2{
		A0: emulated.ValueOf[emparams.BLS12381Fp](0),
		A1: emulated.ValueOf[emparams.BLS12381Fp](240),
	}
	coeff_b := fields_bls12381.E2{
		A0: emulated.ValueOf[emparams.BLS12381Fp](1012),
		A1: emulated.ValueOf[emparams.BLS12381Fp](1012),
	}

	one := emulated.ValueOf[emulated.BLS12381Fp](1)
	two := emulated.ValueOf[emulated.BLS12381Fp](2)
	zeta := fields_bls12381.E2{
		A0: *fp.Neg(&two),
		A1: *fp.Neg(&one),
	}

	return &sswuMapper{
		A:    coeff_a,
		B:    coeff_b,
		Z:    zeta,
		ext2: ext2,
		fp:   fp,
		api:  api,
		iso:  newIsogeny(),
	}
}

// Apply the Simplified SWU for the E' curve (RFC 9380 Section 6.6.3)
func (m sswuMapper) mapToCurve(u fields_bls12381.E2) *G2Affine {
	// SSWU Steps:
	// 1.  tv1 = u^2
	tv1 := m.ext2.Square(&u)
	// 2.  tv1 = Z * tv1
	tv1 = m.ext2.Mul(&m.Z, tv1)
	// 3.  tv2 = tv1^2
	tv2 := m.ext2.Square(tv1)
	// 4.  tv2 = tv2 + tv1
	tv2 = m.ext2.Add(tv2, tv1)
	// 5.  tv3 = tv2 + 1
	tv3 := m.ext2.Add(tv2, m.ext2.One())
	// 6.  tv3 = B * tv3
	tv3 = m.ext2.Mul(&m.B, tv3)
	// 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	s1 := m.ext2.IsZero(tv2)
	tv4 := m.ext2.Select(s1, &m.Z, m.ext2.Neg(tv2))
	// 8.  tv4 = A * tv4
	tv4 = m.ext2.Mul(&m.A, tv4)
	// 9.  tv2 = tv3^2
	tv2 = m.ext2.Square(tv3)
	// 10. tv6 = tv4^2
	tv6 := m.ext2.Square(tv4)
	// 11. tv5 = A * tv6
	tv5 := m.ext2.Mul(&m.A, tv6)
	// 12. tv2 = tv2 + tv5
	tv2 = m.ext2.Add(tv2, tv5)
	// 13. tv2 = tv2 * tv3
	tv2 = m.ext2.Mul(tv2, tv3)
	// 14. tv6 = tv6 * tv4
	tv6 = m.ext2.Mul(tv6, tv4)
	// 15. tv5 = B * tv6
	tv5 = m.ext2.Mul(&m.B, tv6)
	// 16. tv2 = tv2 + tv5
	tv2 = m.ext2.Add(tv2, tv5)
	// 17.   x = tv1 * tv3
	x := m.ext2.Mul(tv1, tv3)
	// 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	isGx1Square, y1 := m.sqrtRatio(tv2, tv6)
	// 19.   y = tv1 * u
	y := m.ext2.Mul(tv1, &u)
	// 20.   y = y * y1
	y = m.ext2.Mul(y, y1)
	// 21.   x = CMOV(x, tv3, is_gx1_square)
	x = m.ext2.Select(isGx1Square, tv3, x)
	// 22.   y = CMOV(y, y1, is_gx1_square)
	y = m.ext2.Select(isGx1Square, y1, y)
	// 23.  e1 = sgn0(u) == sgn0(y)
	sgn0U := m.sgn0(&u)
	sgn0Y := m.sgn0(y)
	diff := m.api.Sub(sgn0U, sgn0Y)
	e1 := m.api.IsZero(diff)
	// 24.   y = CMOV(-y, y, e1)
	yNeg := m.ext2.Neg(y)
	y = m.ext2.Select(e1, y, yNeg)
	// 25.   x = x / tv4
	x = m.ext2.DivUnchecked(x, tv4)
	// 26. return (x, y)
	return &G2Affine{
		P: g2AffP{X: *x, Y: *y},
	}
}

func (m sswuMapper) sgn0(x *fields_bls12381.E2) frontend.Variable {
	// Steps for sgn0_m_eq_2
	// 1. sign_0 = x_0 mod 2
	x0 := m.fp.ToBits(&x.A0)
	sign0 := x0[0]
	// 2. zero_0 = x_0 == 0
	zero0 := m.fp.IsZero(&x.A0)
	// 3. sign_1 = x_1 mod 2
	x1 := m.fp.ToBits(&x.A1)
	sign1 := x1[0]
	// 4. s = sign_0 OR (zero_0 AND sign_1) # Avoid short-circuit logic ops
	tv := m.api.And(zero0, sign1)
	s := m.api.Or(sign0, tv)
	// 5. return s
	return s
}

// Let's not mechanically translate the spec algorithm (Section F.2.1) into R1CS circuits.
// We could simply compute the result as a hint, then apply proper constraints, which is:
// for output of (b, y)
//
//	b1 := {b = True AND y^2 * v = u}
//	b2 := {b = False AND y^2 * v = Z * u}
//	AssertTrue: {b1 OR b2}
func (m sswuMapper) sqrtRatio(u, v *fields_bls12381.E2) (frontend.Variable, *fields_bls12381.E2) {
	// Steps
	// 1. extract the base values of u, v, then compute G2SqrtRatio with gnark-crypto
	x, err := m.fp.NewHint(GetHints()[0], 3, &u.A0, &u.A1, &v.A0, &v.A1)
	if err != nil {
		panic("failed to calculate sqrtRatio with gnark-crypto " + err.Error())
	}

	b := m.fp.IsZero(x[0])
	y := fields_bls12381.E2{A0: *x[1], A1: *x[2]}

	// 2. apply constraints
	// b1 := {b = True AND y^2 * v = u}
	m.api.AssertIsBoolean(b)
	y2 := m.ext2.Square(&y)
	y2v := m.ext2.Mul(y2, v)
	bY2vu := m.ext2.IsZero(m.ext2.Sub(y2v, u))
	b1 := m.api.And(b, bY2vu)

	// b2 := {b = False AND y^2 * v = Z * u}
	uZ := m.ext2.Mul(&m.Z, u)
	bY2vZu := m.ext2.IsZero(m.ext2.Sub(y2v, uZ))
	nb := m.api.IsZero(b)
	b2 := m.api.And(nb, bY2vZu)

	cmp := m.api.Or(b1, b2)
	m.api.AssertIsEqual(cmp, 1)

	return b, &y
}

type g2Polynomial []fields_bls12381.E2

func (p g2Polynomial) eval(m *sswuMapper, at fields_bls12381.E2) (pAt *fields_bls12381.E2) {
	pAt = &p[len(p)-1]

	for i := len(p) - 2; i >= 0; i-- {
		pAt = m.ext2.Mul(pAt, &at)
		pAt = m.ext2.Add(pAt, &p[i])
	}

	return
}

type isogeny struct {
	x_numerator, x_denominator, y_numerator, y_denominator g2Polynomial
}

func newIsogeny() *isogeny {
	return &isogeny{
		x_numerator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542",
				"889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542"),
			*e2FromStrings(
				"0",
				"2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706522"),
			*e2FromStrings(
				"2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706526",
				"1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853261"),
			*e2FromStrings(
				"3557697382419259905260257622876359250272784728834673675850718343221361467102966990615722337003569479144794908942033",
				"0"),
		}),
		x_denominator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"0",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559715"),
			*e2FromStrings(
				"12",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559775"),
			*e2FromStrings(
				"1",
				"0"),
		}),
		y_numerator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558",
				"3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558"),
			*e2FromStrings(
				"0",
				"889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235518"),
			*e2FromStrings(
				"2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706524",
				"1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853263"),
			*e2FromStrings(
				"2816510427748580758331037284777117739799287910327449993381818688383577828123182200904113516794492504322962636245776",
				"0"),
		}),
		y_denominator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355"),
			*e2FromStrings(
				"0",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559571"),
			*e2FromStrings(
				"18",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559769"),
			*e2FromStrings(
				"1",
				"0"),
		}),
	}
}

// Map the point from E' to E
func (m sswuMapper) isogeny(x, y *fields_bls12381.E2) *G2Affine {
	xn := m.iso.x_numerator.eval(&m, *x)

	xd := m.iso.x_denominator.eval(&m, *x)
	xdInv := m.ext2.Inverse(xd)

	yn := m.iso.y_numerator.eval(&m, *x)
	yn = m.ext2.Mul(yn, y)

	yd := m.iso.y_denominator.eval(&m, *x)
	ydInv := m.ext2.Inverse(yd)

	return &G2Affine{
		P: g2AffP{
			X: *m.ext2.Mul(xn, xdInv),
			Y: *m.ext2.Mul(yn, ydInv),
		},
	}
}

func e2FromStrings(x, y string) *fields_bls12381.E2 {
	A0, _ := new(big.Int).SetString(x, 10)
	A1, _ := new(big.Int).SetString(y, 10)

	a0 := emulated.ValueOf[emulated.BLS12381Fp](A0)
	a1 := emulated.ValueOf[emulated.BLS12381Fp](A1)

	return &fields_bls12381.E2{A0: a0, A1: a1}
}

// Follow RFC 9380 Apendix G.3 to compute efficiently.
func clearCofactor(g2 *G2, fp *emulated.Field[emparams.BLS12381Fp], p *G2Affine) *G2Affine {
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
	t2 = g2.addUnified(t1, t2)
	// 7.  t2 = c1 * t2
	t2 = g2.scalarMulBySeed(t2)
	// 8.  t3 = t3 + t2
	t3 = g2.addUnified(t3, t2)
	// 9.  t3 = t3 - t1
	t3 = g2.sub(t3, t1)
	// 10.  Q = t3 - P
	Q := g2.sub(t3, p)
	// 11. return Q
	return Q
}
