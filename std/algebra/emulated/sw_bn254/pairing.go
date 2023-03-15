package sw_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	*fields_bn254.Ext12
	curveF *emulated.Field[emulated.BN254Fp]
}

type GTEl = fields_bn254.E12

func NewGTEl(v bn254.GT) GTEl {
	return GTEl{
		C0: fields_bn254.E6{
			B0: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B0.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B0.A1),
			},
			B1: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B1.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B1.A1),
			},
			B2: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B2.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B2.A1),
			},
		},
		C1: fields_bn254.E6{
			B0: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B0.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B0.A1),
			},
			B1: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B1.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B1.A1),
			},
			B2: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B2.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B2.A1),
			},
		},
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		Ext12:  fields_bn254.NewExt12(ba),
		curveF: ba,
	}, nil
}

// FinalExponentiation computes the exponentiation eᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r.
//
// We use instead d'= s ⋅ d, where s is the cofactor
//
//	2x₀(6x₀²+3x₀+1)
//
// and r does NOT divide d'
func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	var t [4]*GTEl

	// Easy part
	// (p⁶-1)(p²+1)
	t[0] = pr.Ext12.Conjugate(e)
	t[0] = pr.Ext12.DivUnchecked(t[0], e)
	result := pr.Ext12.FrobeniusSquare(t[0])
	result = pr.Ext12.Mul(result, t[0])

	// Hard part (up to permutation)
	// 2x₀(6x₀²+3x₀+1)(p⁴-p²+1)/r
	// Duquesne and Ghammam
	// https://eprint.iacr.org/2015/192.pdf
	// Fuentes et al. variant (alg. 10)
	t[0] = pr.Ext12.Expt(result)
	t[0] = pr.Ext12.Conjugate(t[0])
	t[0] = pr.Ext12.CyclotomicSquare(t[0])
	t[2] = pr.Ext12.Expt(t[0])
	t[2] = pr.Ext12.Conjugate(t[2])
	t[1] = pr.Ext12.CyclotomicSquare(t[2])
	t[2] = pr.Ext12.Mul(t[2], t[1])
	t[2] = pr.Ext12.Mul(t[2], result)
	t[1] = pr.Ext12.Expt(t[2])
	t[1] = pr.Ext12.CyclotomicSquare(t[1])
	t[1] = pr.Ext12.Mul(t[1], t[2])
	t[1] = pr.Ext12.Conjugate(t[1])
	t[3] = pr.Ext12.Conjugate(t[1])
	t[1] = pr.Ext12.CyclotomicSquare(t[0])
	t[1] = pr.Ext12.Mul(t[1], result)
	t[1] = pr.Ext12.Conjugate(t[1])
	t[1] = pr.Ext12.Mul(t[1], t[3])
	t[0] = pr.Ext12.Mul(t[0], t[1])
	t[2] = pr.Ext12.Mul(t[2], t[1])
	t[3] = pr.Ext12.FrobeniusSquare(t[1])
	t[2] = pr.Ext12.Mul(t[2], t[3])
	t[3] = pr.Ext12.Conjugate(result)
	t[3] = pr.Ext12.Mul(t[3], t[0])
	t[1] = pr.Ext12.FrobeniusCube(t[3])
	t[2] = pr.Ext12.Mul(t[2], t[1])
	t[1] = pr.Ext12.Frobenius(t[0])
	t[1] = pr.Ext12.Mul(t[1], t[2])

	return t[1]
}

func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.FinalExponentiation(res)
	return res, nil
}

func (pr Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
}

// loopCounter = 6*seed+2 in 2-NAF
var loopCounter = [66]int8{
	0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
	0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
	-1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
	-1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
}

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 - R0*(x/y) - R1*(1/y) = 0 instead of R0'*y - R1'*x - R2' = 0
// This makes the multiplication by lines (MulBy034) circuit-efficient.
type lineEvaluation struct {
	R0, R1 fields_bn254.E2
}

// MillerLoop computes the multi-Miller loop
func (pr Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}

	res := pr.Ext12.One()

	var l1, l2 *lineEvaluation
	Qacc := make([]*G2Affine, n)
	QNeg := make([]*G2Affine, n)
	yInv := make([]*emulated.Element[emulated.BN254Fp], n)
	xOverY := make([]*emulated.Element[emulated.BN254Fp], n)

	for k := 0; k < n; k++ {
		Qacc[k] = Q[k]
		QNeg[k] = &G2Affine{X: Q[k].X, Y: *pr.Ext2.Neg(&Q[k].Y)}
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xOverY[k] = pr.curveF.Div(&P[k].X, &P[k].Y)
	}

	// k = 0
	Qacc[0], l1 = pr.doubleStep(Qacc[0])
	res.C1.B0 = *pr.MulByElement(&l1.R0, xOverY[0])
	res.C1.B1 = *pr.MulByElement(&l1.R1, yInv[0])

	if n >= 2 {
		// k = 1
		Qacc[1], l1 = pr.doubleStep(Qacc[1])
		l1.R0 = *pr.MulByElement(&l1.R0, xOverY[1])
		l1.R1 = *pr.MulByElement(&l1.R1, yInv[1])
		res = pr.Mul034By034(&l1.R0, &l1.R1, &res.C1.B0, &res.C1.B1)
	}

	if n >= 3 {
		// k >= 2
		for k := 2; k < n; k++ {
			Qacc[k], l1 = pr.doubleStep(Qacc[k])
			l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
			l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
			res = pr.MulBy034(res, &l1.R0, &l1.R1)
		}
	}

	for i := len(loopCounter) - 3; i >= 0; i-- {
		res = pr.Square(res)

		switch loopCounter[i] {

		case 0:
			for k := 0; k < n; k++ {
				Qacc[k], l1 = pr.doubleStep(Qacc[k])
				l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
				l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
				res = pr.MulBy034(res, &l1.R0, &l1.R1)
			}

		case 1:
			for k := 0; k < n; k++ {
				Qacc[k], l1, l2 = pr.doubleAndAddStep(Qacc[k], Q[k])
				l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
				l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
				res = pr.MulBy034(res, &l1.R0, &l1.R1)
				l2.R0 = *pr.MulByElement(&l2.R0, xOverY[k])
				l2.R1 = *pr.MulByElement(&l2.R1, yInv[k])
				res = pr.MulBy034(res, &l2.R0, &l2.R1)
			}

		case -1:
			for k := 0; k < n; k++ {
				Qacc[k], l1, l2 = pr.doubleAndAddStep(Qacc[k], QNeg[k])
				l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
				l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
				res = pr.MulBy034(res, &l1.R0, &l1.R1)
				l2.R0 = *pr.MulByElement(&l2.R0, xOverY[k])
				l2.R1 = *pr.MulByElement(&l2.R1, yInv[k])
				res = pr.MulBy034(res, &l2.R0, &l2.R1)
			}

		default:
			return nil, errors.New("invalid loopCounter")
		}
	}

	Q1, Q2 := new(G2Affine), new(G2Affine)
	for k := 0; k < n; k++ {
		//Q1 = π(Q)
		Q1.X = *pr.Ext12.Ext2.Conjugate(&Q[k].X)
		Q1.X = *pr.Ext12.Ext2.MulByNonResidue1Power2(&Q1.X)
		Q1.Y = *pr.Ext12.Ext2.Conjugate(&Q[k].Y)
		Q1.Y = *pr.Ext12.Ext2.MulByNonResidue1Power3(&Q1.Y)

		// Q2 = -π²(Q)
		Q2.X = *pr.Ext12.Ext2.MulByNonResidue2Power2(&Q[k].X)
		Q2.Y = *pr.Ext12.Ext2.MulByNonResidue2Power3(&Q[k].Y)
		Q2.Y = *pr.Ext12.Ext2.Neg(&Q2.Y)

		Qacc[k], l1 = pr.addStep(Qacc[k], Q1)
		l1.R0 = *pr.Ext2.MulByElement(&l1.R0, xOverY[k])
		l1.R1 = *pr.Ext2.MulByElement(&l1.R1, yInv[k])
		res = pr.MulBy034(res, &l1.R0, &l1.R1)

		l2 = pr.addStepLineOnly(Qacc[k], Q2)
		l2.R0 = *pr.MulByElement(&l2.R0, xOverY[k])
		l2.R1 = *pr.MulByElement(&l2.R1, yInv[k])
		res = pr.MulBy034(res, &l2.R0, &l2.R1)

	}

	return res, nil
}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *G2Affine) (*G2Affine, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p G2Affine

	// compute lambda1 = (y2-y1)/(x2-x1)
	n := pr.Ext2.Sub(&p1.Y, &p2.Y)
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	l1 := pr.Ext2.DivUnchecked(n, d)

	// x3 =lambda1**2-p1.x-p2.x
	x3 := pr.Ext2.Square(l1)
	x3 = pr.Ext2.Sub(x3, &p1.X)
	x3 = pr.Ext2.Sub(x3, &p2.X)

	// omit y3 computation

	// compute line1
	line1.R0 = *pr.Ext2.Neg(l1)
	line1.R1 = *pr.Ext2.Mul(l1, &p1.X)
	line1.R1 = *pr.Ext2.Sub(&line1.R1, &p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n = pr.Ext2.Double(&p1.Y)
	d = pr.Ext2.Sub(x3, &p1.X)
	l2 := pr.Ext2.DivUnchecked(n, d)
	l2 = pr.Ext2.Add(l2, l1)
	l2 = pr.Ext2.Neg(l2)

	// compute x4 = lambda2**2-x1-x3
	x4 := pr.Ext2.Square(l2)
	x4 = pr.Ext2.Sub(x4, &p1.X)
	x4 = pr.Ext2.Sub(x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4 := pr.Ext2.Sub(&p1.X, x4)
	y4 = pr.Ext2.Mul(l2, y4)
	y4 = pr.Ext2.Sub(y4, &p1.Y)

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *pr.Ext2.Neg(l2)
	line2.R1 = *pr.Ext2.Mul(l2, &p1.X)
	line2.R1 = *pr.Ext2.Sub(&line2.R1, &p1.Y)

	return &p, &line1, &line2
}

// doubleStep doubles a point in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleStep(p1 *G2Affine) (*G2Affine, *lineEvaluation) {

	var p G2Affine
	var line lineEvaluation

	// lambda = 3*p1.x**2/2*p.y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	l := pr.Ext2.DivUnchecked(n, d)

	// xr = lambda**2-2*p1.x
	xr := pr.Ext2.Square(l)
	xr = pr.Ext2.Sub(xr, &p1.X)
	xr = pr.Ext2.Sub(xr, &p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr = pr.Ext2.Mul(l, yr)
	yr = pr.Ext2.Sub(yr, &p1.Y)

	p.X = *xr
	p.Y = *yr

	line.R0 = *pr.Ext2.Neg(l)
	line.R1 = *pr.Ext2.Mul(l, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &p, &line

}

// addStep adds two points in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) addStep(p, q *G2Affine) (*G2Affine, *lineEvaluation) {

	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := pr.Ext2.Sub(&q.Y, &p.Y)
	qxpx := pr.Ext2.Sub(&q.X, &p.X)
	λ := pr.Ext2.DivUnchecked(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := pr.Ext2.Square(λ)
	qxpx = pr.Ext2.Add(&p.X, &q.X)
	xr := pr.Ext2.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := pr.Ext2.Sub(&p.X, xr)
	λpxrx := pr.Ext2.Mul(λ, pxrx)
	yr := pr.Ext2.Sub(λpxrx, &p.Y)

	var res G2Affine
	res.X = *xr
	res.Y = *yr

	var line lineEvaluation
	line.R0 = *pr.Ext2.Neg(λ)
	line.R1 = *pr.Ext2.Mul(λ, &p.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p.Y)

	return &res, &line

}

// addStepLineOnly computes the line that goes through p and q but does not compute p+q
func (pr Pairing) addStepLineOnly(p, q *G2Affine) *lineEvaluation {

	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := pr.Ext2.Sub(&q.Y, &p.Y)
	qxpx := pr.Ext2.Sub(&q.X, &p.X)
	λ := pr.Ext2.DivUnchecked(qypy, qxpx)

	var line lineEvaluation
	line.R0 = *pr.Ext2.Neg(λ)
	line.R1 = *pr.Ext2.Mul(λ, &p.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p.Y)

	return &line

}
