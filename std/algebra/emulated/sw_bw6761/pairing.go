package sw_bw6761

import (
	"errors"
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bw6761.Ext6
	curveF *emulated.Field[emulated.BW6761Fp]
}

type GTEl = fields_bw6761.E6

func NewGTEl(v bw6761.GT) GTEl {
	return GTEl{
		B0: fields_bw6761.E3{
			A0: emulated.ValueOf[emulated.BW6761Fp](v.B0.A0),
			A1: emulated.ValueOf[emulated.BW6761Fp](v.B0.A1),
			A2: emulated.ValueOf[emulated.BW6761Fp](v.B0.A2),
		},
		B1: fields_bw6761.E3{
			A0: emulated.ValueOf[emulated.BW6761Fp](v.B1.A0),
			A1: emulated.ValueOf[emulated.BW6761Fp](v.B1.A1),
			A2: emulated.ValueOf[emulated.BW6761Fp](v.B1.A2),
		},
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		api:    api,
		Ext6:   fields_bw6761.NewExt6(api),
		curveF: ba,
	}, nil
}

// FinalExponentiation computes the exponentiation zᵈ where
//
// d = (p⁶-1)/r = (p⁶-1)/Φ₆(p) ⋅ Φ₆(p)/r = (p³-1)(p+1)(p²-p+1)/r
//
// we use instead d = s⋅(p³-1)(p+1)(p²-p+1)/r
// where s is the cofactor 12(x₀+1) (El Housni and Guillevic)
// https://eprint.iacr.org/2020/351.pdf
func (pr Pairing) FinalExponentiation(z *GTEl) *GTEl {

	result := pr.Copy(z)

	// 1. Easy part
	// (p³-1)(p+1)
	buf := pr.Conjugate(result)
	buf = pr.DivUnchecked(buf, result)
	result = pr.Frobenius(buf)
	result = pr.Mul(result, buf)

	// 2. Hard part (up to permutation)
	// 12(x₀+1)(p²-p+1)/r
	// El Housni and Guillevic
	// https://eprint.iacr.org/2020/351.pdf
	m1 := pr.Expt(result)
	_m1 := pr.Conjugate(m1)
	m2 := pr.Expt(m1)
	_m2 := pr.Conjugate(m2)
	m3 := pr.Expt(m2)
	f0 := pr.Frobenius(result)
	f0 = pr.Mul(f0, result)
	f0 = pr.Mul(f0, m2)
	m2 = pr.CyclotomicSquare(_m1)
	f0 = pr.Mul(f0, m2)
	f0_36 := pr.CyclotomicSquareCompressed(f0)
	f0_36 = pr.CyclotomicSquareCompressed(f0_36)
	f0_36 = pr.CyclotomicSquareCompressed(f0_36)
	f0_36 = pr.DecompressKarabina(f0_36)
	f0_36 = pr.Mul(f0_36, f0)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.CyclotomicSquare(f0_36)
	g0 := pr.Mul(result, m1)
	g0 = pr.Frobenius(g0)
	g0 = pr.Mul(g0, m3)
	g0 = pr.Mul(g0, _m2)
	g0 = pr.Mul(g0, _m1)
	g1 := pr.Expt(g0)
	_g1 := pr.Conjugate(g1)
	g2 := pr.Expt(g1)
	g3 := pr.Expt(g2)
	_g3 := pr.Conjugate(g3)
	g4 := pr.Expt(g3)
	_g4 := pr.Conjugate(g4)
	g5 := pr.Expt(g4)
	_g5 := pr.Conjugate(g5)
	g6 := pr.Expt(g5)
	gA := pr.Mul(g3, _g5)
	gA = pr.CyclotomicSquare(gA)
	gA = pr.Mul(gA, g6)
	gA = pr.Mul(gA, g1)
	gA = pr.Mul(gA, g0)
	g034 := pr.Mul(g0, g3)
	g034 = pr.Mul(g034, _g4)
	gB := pr.CyclotomicSquare(g034)
	gB = pr.Mul(gB, g034)
	gB = pr.Mul(gB, g5)
	gB = pr.Mul(gB, _g1)
	_g1g2 := pr.Mul(_g1, g2)
	gC := pr.Mul(_g3, _g1g2)
	gC = pr.CyclotomicSquare(gC)
	gC = pr.Mul(gC, _g1g2)
	gC = pr.Mul(gC, g0)
	gC = pr.CyclotomicSquare(gC)
	gC = pr.Mul(gC, g2)
	gC = pr.Mul(gC, g0)
	gC = pr.Mul(gC, g4)

	// ht, hy = 13, 9
	// c1 = ht²+3hy² = 412
	h1 := pr.Expc1(gA)
	// c2 = ht+hy = 22
	h2 := pr.Expc2(gB)
	h2g2C := pr.CyclotomicSquare(gC)
	h2g2C = pr.Mul(h2g2C, h2)
	h4 := pr.CyclotomicSquare(h2g2C)
	h4 = pr.Mul(h4, h2g2C)
	h4 = pr.CyclotomicSquare(h4)
	result = pr.Mul(h1, h4)
	result = pr.Mul(result, f0_36)

	return result
}

// lineEvaluation represents a sparse Fp6 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014) circuit-efficient.
type lineEvaluation struct {
	R0, R1 emulated.Element[emulated.BW6761Fp]
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroup. See IsInSubGroup.
func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	f, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, err
	}
	return pr.FinalExponentiation(f), nil
}

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	f, err := pr.Pair(P, Q)
	if err != nil {
		return err

	}
	one := pr.One()
	pr.AssertIsEqual(f, one)

	return nil
}

func (pr Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext6.AssertIsEqual(x, y)
}

// seed x₀=9586122913090633729
//
// loopCounter1 = x₀+1 in binary
var loopCounter1 = [64]int8{
	0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
	0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1,
}

// loopCounter2 = (x₀-1)² in 2-NAF
var loopCounter2 = [127]int8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, -1, 0,
	1, 0, -1, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0,
	0, 0, 1,
}

// millerLoopSingle computes the Miller loop
//
// f_{u+1,Q}(P) * (f_{u+1})^q_{u²-2u-1,[u+1]Q}(P) * l^q_{[(u+1)(u²-2u+1)]Q,-Q}(P)
//
//	Eq (4') in https://hackmd.io/@gnark/BW6-761-changes
func (pr Pairing) millerLoopSingle(P *G1Affine, Q *G2Affine) (*GTEl, error) {

	var l1, l2 *lineEvaluation
	var yInv, xNegOverY *emulated.Element[emulated.BW6761Fp]

	// 1. f1 = f_{u+1,Q}(P)
	res1 := pr.Ext6.One()
	Qacc := Q
	yInv = pr.curveF.Inverse(&P.Y)
	xNegOverY = pr.curveF.MulMod(&P.X, yInv)
	xNegOverY = pr.curveF.Neg(xNegOverY)

	// i = 62, separately to avoid an E6 Square
	// (Square(res) = 1² = 1)

	// Qacc ← 2Qacc and l1 the tangent ℓ passing 2Qacc
	Qacc, l1 = pr.doubleStep(Qacc)
	// line evaluation at P
	// and assign line to res1 (R1, R0, 0, 0, 1, 0)
	res1.B0.A0 = *pr.curveF.Mul(&l1.R1, yInv)
	res1.B0.A1 = *pr.curveF.Mul(&l1.R0, xNegOverY)
	res1.B1.A1 = *pr.curveF.One()

	for i := 61; i >= 0; i-- {
		// f²
		res1 = pr.Square(res1)

		if loopCounter1[i] == 0 {
			// Qacc ← 2Qacc and l1 the tangent ℓ passing 2Qacc
			Qacc, l1 = pr.doubleStep(Qacc)

			// line evaluation at P
			l1.R0 = *pr.curveF.Mul(&l1.R0, xNegOverY)
			l1.R1 = *pr.curveF.Mul(&l1.R1, yInv)
			res1 = pr.MulBy014(res1, &l1.R1, &l1.R0)

		} else {
			// Qacc ← 2Qacc+Q,
			// l1 the line ℓ passing Qacc and Q
			// l2 the line ℓ passing (Qacc+Q) and Qacc
			Qacc, l1, l2 = pr.doubleAndAddStep(Qacc, Q)

			// line evaluation at P
			l1.R0 = *pr.curveF.Mul(&l1.R0, xNegOverY)
			l1.R1 = *pr.curveF.Mul(&l1.R1, yInv)
			res1 = pr.MulBy014(res1, &l1.R1, &l1.R0)

			// line evaluation at P
			l2.R0 = *pr.curveF.Mul(&l2.R0, xNegOverY)
			l2.R1 = *pr.curveF.Mul(&l2.R1, yInv)
			res1 = pr.MulBy014(res1, &l2.R1, &l2.R0)

		}
	}

	// Cache values for the second Miller loop
	res1Cached := res1
	res1Inv := pr.Conjugate(res1)
	uQ := Qacc

	// 2. f2 = f_{u²-2u+1,uQ}(P)
	res2 := res1Cached
	uQNeg := &G2Affine{X: uQ.X, Y: *pr.curveF.Neg(&uQ.Y)}

	for i := 125; i >= 0; i-- {
		// f²
		res2 = pr.Square(res2)

		switch loopCounter2[i] {

		case 0:
			// Qacc ← 2Qacc and l1 the tangent ℓ passing 2Qacc
			Qacc, l1 = pr.doubleStep(Qacc)

			// line evaluation at P
			l1.R0 = *pr.curveF.Mul(&l1.R0, xNegOverY)
			l1.R1 = *pr.curveF.Mul(&l1.R1, yInv)
			res2 = pr.MulBy014(res2, &l1.R1, &l1.R0)

		case 1:
			// Qacc ← 2Qacc+uQ,
			// l1 the line ℓ passing Qacc and uQ
			// l2 the line ℓ passing (Qacc+uQ) and Qacc
			Qacc, l1, l2 = pr.doubleAndAddStep(Qacc, uQ)

			// line evaluation at P
			l1.R0 = *pr.curveF.Mul(&l1.R0, xNegOverY)
			l1.R1 = *pr.curveF.Mul(&l1.R1, yInv)
			res2 = pr.MulBy014(res2, &l1.R1, &l1.R0)

			// line evaluation at P
			l2.R0 = *pr.curveF.Mul(&l2.R0, xNegOverY)
			l2.R1 = *pr.curveF.Mul(&l2.R1, yInv)
			res2 = pr.MulBy014(res2, &l2.R1, &l2.R0)
			res2 = pr.Mul(res2, res1Cached)

		case -1:
			// Qacc ← 2Qacc-uQ,
			// l1 the line ℓ passing Qacc and -uQ
			// l2 the line ℓ passing (Qacc-uQ) and Qacc
			Qacc, l1, l2 = pr.doubleAndAddStep(Qacc, uQNeg)

			// line evaluation at P
			l1.R0 = *pr.curveF.Mul(&l1.R0, xNegOverY)
			l1.R1 = *pr.curveF.Mul(&l1.R1, yInv)
			res2 = pr.MulBy014(res2, &l1.R1, &l1.R0)

			// line evaluation at P
			l2.R0 = *pr.curveF.Mul(&l2.R0, xNegOverY)
			l2.R1 = *pr.curveF.Mul(&l2.R1, yInv)
			res2 = pr.MulBy014(res2, &l2.R1, &l2.R0)
			res2 = pr.Mul(res2, res1Inv)

		default:
			return nil, errors.New("invalid loopCounter")
		}
	}

	// 3. l_{(u+1)vQ,-Q}(P)
	QNeg := &G2Affine{X: Q.X, Y: *pr.curveF.Neg(&Q.Y)}
	l1 = pr.lineCompute(Qacc, QNeg)
	l1.R0 = *pr.curveF.Mul(&l1.R0, xNegOverY)
	l1.R1 = *pr.curveF.Mul(&l1.R1, yInv)

	// f2 = f2 * l_{(u+1)vQ,-Q}(P)
	res2 = pr.MulBy014(res2, &l1.R1, &l1.R0)

	// 4. f1 * f2^q
	res2 = pr.Frobenius(res2)
	res := pr.Mul(res1, res2)

	return res, nil
}

// MillerLoop computes the multi-Miller loop
func (pr Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}

	res := pr.Ext6.One()

	// k = 0
	res, err := pr.millerLoopSingle(P[0], Q[0])
	if err != nil {
		return &GTEl{}, err
	}

	for k := 1; k < n; k++ {
		m, err := pr.millerLoopSingle(P[k], Q[k])
		if err != nil {
			return &GTEl{}, err
		}
		res = pr.Mul(res, m)
	}

	return res, nil

}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *G2Affine) (*G2Affine, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p G2Affine

	// compute λ1 = (y2-y1)/(x2-x1)
	n := pr.curveF.Sub(&p1.Y, &p2.Y)
	d := pr.curveF.Sub(&p1.X, &p2.X)
	l1 := pr.curveF.Div(n, d)

	// compute x3 =λ1²-x1-x2
	x3 := pr.curveF.Mul(l1, l1)
	x3 = pr.curveF.Sub(x3, &p1.X)
	x3 = pr.curveF.Sub(x3, &p2.X)

	// omit y3 computation

	// compute line1
	line1.R0 = *l1
	line1.R1 = *pr.curveF.Mul(l1, &p1.X)
	line1.R1 = *pr.curveF.Sub(&line1.R1, &p1.Y)

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.curveF.Add(&p1.Y, &p1.Y)
	d = pr.curveF.Sub(x3, &p1.X)
	l2 := pr.curveF.Div(n, d)
	l2 = pr.curveF.Add(l2, l1)
	l2 = pr.curveF.Neg(l2)

	// compute x4 = λ2²-x1-x3
	x4 := pr.curveF.Mul(l2, l2)
	x4 = pr.curveF.Sub(x4, &p1.X)
	x4 = pr.curveF.Sub(x4, x3)

	// compute y4 = λ2(x1 - x4)-y1
	y4 := pr.curveF.Sub(&p1.X, x4)
	y4 = pr.curveF.Mul(l2, y4)
	y4 = pr.curveF.Sub(y4, &p1.Y)

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *l2
	line2.R1 = *pr.curveF.Mul(l2, &p1.X)
	line2.R1 = *pr.curveF.Sub(&line2.R1, &p1.Y)

	return &p, &line1, &line2
}

// doubleStep doubles a point in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleStep(p1 *G2Affine) (*G2Affine, *lineEvaluation) {

	var p G2Affine
	var line lineEvaluation

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	three := big.NewInt(3)
	n = pr.curveF.MulConst(n, three)
	d := pr.curveF.Add(&p1.Y, &p1.Y)
	λ := pr.curveF.Div(n, d)

	// xr = λ²-2x
	xr := pr.curveF.Mul(λ, λ)
	xr = pr.curveF.Sub(xr, &p1.X)
	xr = pr.curveF.Sub(xr, &p1.X)

	// yr = λ(x-xr)-y
	yr := pr.curveF.Sub(&p1.X, xr)
	yr = pr.curveF.Mul(λ, yr)
	yr = pr.curveF.Sub(yr, &p1.Y)

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &p, &line

}

// lineCompute computes the line that goes through p1 and p2 but does not compute p1+p2
func (pr Pairing) lineCompute(p1, p2 *G2Affine) *lineEvaluation {

	// compute λ = (y2-y1)/(x2-x1)
	qypy := pr.curveF.Sub(&p2.Y, &p1.Y)
	qxpx := pr.curveF.Sub(&p2.X, &p1.X)
	λ := pr.curveF.Div(qypy, qxpx)

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &line

}

// --- Alternative Miller loop ---
var thirdRootOneG2 = emulated.ValueOf[emulated.BW6761Fp]("3876905175468200631077310367084681598448315841795389501393935922030716896759491089791062239139884430736136043081596370525752532152533918168748948422532524762769433379258873205270018176434449950195784127083892851850798970002242935133594411783692478449434154543435837344414891700653141782682622592665272535258486114040810216200011591719198498884598067930925845038459634787676665023756334020972459098834655430741989740290995313870292460737326506741396444022500")

var loopCounterAlt1 = [190]int8{
	0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0,
	0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}
var loopCounterAlt2 = [190]int8{
	-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, -1,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1,
	0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, 1, 0, 0, 1, 0, -1, 0, 1, 0,
	1, 0, 0, 0, 1, 0, -1, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, 1,
}

func (pr Pairing) MillerLoopAlt(P *G1Affine, Q *G2Affine) (*GTEl, error) {

	// precomputations
	var yInv, xNegOverY *emulated.Element[emulated.BW6761Fp]
	yInv = pr.curveF.Inverse(&Q.Y)
	xNegOverY = pr.curveF.MulMod(&Q.X, yInv)
	xNegOverY = pr.curveF.Neg(xNegOverY)
	p0 := &G1Affine{X: P.X, Y: P.Y}
	p0neg := &G1Affine{X: p0.X, Y: *pr.curveF.Neg(&p0.Y)}
	p1 := &G1Affine{
		X: *pr.curveF.MulMod(&p0.X, &thirdRootOneG2),
		Y: *pr.curveF.Neg(&p0.Y),
	}
	p1neg := &G1Affine{X: p1.X, Y: *pr.curveF.Neg(&p1.Y)}

	// l_{p0,p1}(q)
	p01, l01 := pr.addStep(p0, p1)
	l01.R0 = *pr.curveF.MulMod(&l01.R0, xNegOverY)
	l01.R1 = *pr.curveF.MulMod(&l01.R1, yInv)
	p01neg := &G1Affine{X: p01.X, Y: *pr.curveF.Neg(&p01.Y)}

	// l_{p0,-p1}(q)
	p10, l10 := pr.addStep(p0, p1neg)
	l10.R0 = *pr.curveF.MulMod(&l10.R0, xNegOverY)
	l10.R1 = *pr.curveF.MulMod(&l10.R1, yInv)
	p10neg := &G1Affine{X: p10.X, Y: *pr.curveF.Neg(&p10.Y)}

	// f_{a0+\lambda*a1,P}(Q)
	result := pr.Ext6.One()

	var j int8

	// i = 188
	var l *lineEvaluation
	pAcc, l0 := pr.doubleStep(p1)
	l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY)
	l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv)
	result = pr.MulBy034(result, &l0.R0, &l0.R1)

	for i := 187; i >= 1; i-- {
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		j = loopCounterAlt2[i]*3 + loopCounterAlt1[i]

		pAcc, l0 = pr.doubleStep(pAcc)
		l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY)
		l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv)
		result = pr.MulBy034(result, &l0.R0, &l0.R1)

		switch j {
		case -4:
			pAcc, l = pr.addStep(pAcc, p01neg)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
			result = pr.MulBy034(result, &l01.R0, &l01.R1)
		case -3:
			pAcc, l = pr.addStep(pAcc, p1neg)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
		case -2:
			pAcc, l = pr.addStep(pAcc, p10)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
			result = pr.MulBy034(result, &l01.R0, &l01.R1)
		case -1:
			pAcc, l = pr.addStep(pAcc, p0neg)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
		case 0:
			continue
		case 1:
			pAcc, l = pr.addStep(pAcc, p0)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
		case 2:
			pAcc, l = pr.addStep(pAcc, p10neg)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
			result = pr.MulBy034(result, &l01.R0, &l01.R1)
		case 3:
			pAcc, l = pr.addStep(pAcc, p1)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
		case 4:
			pAcc, l = pr.addStep(pAcc, p01)
			l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY)
			l.R1 = *pr.curveF.MulMod(&l.R1, yInv)
			result = pr.MulBy034(result, &l.R0, &l.R1)
			result = pr.MulBy034(result, &l01.R0, &l01.R1)
		default:
			return nil, errors.New("invalid loopCounter")
		}
	}

	// i = 0, j = -3
	result = pr.Square(result)
	pAcc, l0 = pr.doubleStep(pAcc)
	l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY)
	l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv)
	result = pr.MulBy034(result, &l0.R0, &l0.R1)

	return result, nil

}

// addStep adds two points in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) addStep(p1, p2 *G1Affine) (*G1Affine, *lineEvaluation) {

	// compute λ = (y2-y1)/(x2-x1)
	p2ypy := pr.curveF.Sub(&p2.Y, &p1.Y)
	p2xpx := pr.curveF.Sub(&p2.X, &p1.X)
	λ := pr.curveF.Div(p2ypy, p2xpx)

	// xr = λ²-x1-x2
	λλ := pr.curveF.Mul(λ, λ)
	p2xpx = pr.curveF.Add(&p1.X, &p2.X)
	xr := pr.curveF.Sub(λλ, p2xpx)

	// yr = λ(x1-xr) - y1
	pxrx := pr.curveF.Sub(&p1.X, xr)
	λpxrx := pr.curveF.Mul(λ, pxrx)
	yr := pr.curveF.Sub(λpxrx, &p1.Y)

	var res G2Affine
	res.X = *xr
	res.Y = *yr

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &res, &line

}

func (pr Pairing) PairAlt(P *G1Affine, Q *G2Affine) (*GTEl, error) {
	f, err := pr.MillerLoopAlt(P, Q)
	if err != nil {
		return nil, err
	}
	return pr.FinalExponentiation(f), nil
}
