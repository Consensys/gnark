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
// makes the multiplication by lines (MulBy034) and between lines (Mul034By034)
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
// x₀+1 in binary (64 bits) padded with 0s
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

// x₀³-x₀²-x₀ in 2-NAF
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

// thirdRootOne² + thirdRootOne + 1 = 0 in BW6761Fp
var thirdRootOne = emulated.ValueOf[emulated.BW6761Fp]("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648")

// MillerLoop computes the optimal Tate multi-Miller loop
// (or twisted ate or Eta revisited)
//
// ∏ᵢ { fᵢ_{x₀+1+λ(x₀³-x₀²-x₀),Pᵢ}(Qᵢ) }
//
// Alg.2 in https://eprint.iacr.org/2021/1359.pdf
// Eq. (6) in https://hackmd.io/@gnark/BW6-761-changes
func (pr Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations
	p0 := make([]*G1Affine, n)
	p1 := make([]*G1Affine, n)
	p0neg := make([]*G1Affine, n)
	p1neg := make([]*G1Affine, n)
	p01 := make([]*G1Affine, n)
	p10 := make([]*G1Affine, n)
	p01neg := make([]*G1Affine, n)
	p10neg := make([]*G1Affine, n)
	pAcc := make([]*G1Affine, n)
	yInv := make([]*emulated.Element[emulated.BW6761Fp], n)
	xNegOverY := make([]*emulated.Element[emulated.BW6761Fp], n)
	l01 := make([]*lineEvaluation, n)

	for k := 0; k < n; k++ {
		// P and Q are supposed to be on G1 and G2 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&Q[k].Y)
		xNegOverY[k] = pr.curveF.MulMod(&Q[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
		// p0 = P = (x, y)
		p0[k] = &G1Affine{X: P[k].X, Y: P[k].Y}
		// p0neg = -P = (x, -y)
		p0neg[k] = &G1Affine{X: p0[k].X, Y: *pr.curveF.Neg(&p0[k].Y)}
		// p1 = (w*x, -y)
		p1[k] = &G1Affine{X: *pr.curveF.MulMod(&p0[k].X, &thirdRootOne), Y: p0neg[k].Y}
		// p1neg = (w*x, y)
		p1neg[k] = &G1Affine{X: p1[k].X, Y: p0[k].Y}
		// p01 = p0+p1 and l01 line through p0 and p1
		p01[k], l01[k] = pr.addStep(p0[k], p1[k])
		l01[k].R0 = *pr.curveF.MulMod(&l01[k].R0, xNegOverY[k])
		l01[k].R1 = *pr.curveF.MulMod(&l01[k].R1, yInv[k])
		// p01neg = -p01
		p01neg[k] = &G1Affine{X: p01[k].X, Y: *pr.curveF.Neg(&p01[k].Y)}
		// p10 = p0-p1
		p10[k] = &G1Affine{
			X: *pr.curveF.Add(&p0[k].X, &p1[k].X),
			Y: p1[k].Y,
		}
		p10[k].X = *pr.curveF.Neg(&p10[k].X)
		// p10neg = -p10
		p10neg[k] = &G1Affine{X: p10[k].X, Y: p0[k].Y}
		// point accumulator initialized to p1
		pAcc[k] = p1[k]
	}

	// f_{x₀+1+λ(x₀³-x₀²-x₀),P}(Q)
	result := pr.Ext6.One()
	var prodLines [5]emulated.Element[emulated.BW6761Fp]
	var l, l0 *lineEvaluation

	// i = 188, separately to avoid an E6 Square
	// (Square(res) = 1² = 1)
	// k = 0, separately to avoid MulBy034 (res × ℓ)
	// (assign line to res)
	pAcc[0], l0 = pr.doubleStep(p1[0])
	result.B1.A0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[0])
	result.B1.A1 = *pr.curveF.MulMod(&l0.R1, yInv[0])

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		pAcc[1], l0 = pr.doubleStep(pAcc[1])
		l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[1])
		l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[1])
		prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &result.B1.A0, &result.B1.A1)
		result.B0.A0 = prodLines[0]
		result.B0.A1 = prodLines[1]
		result.B0.A2 = prodLines[2]
		result.B1.A0 = prodLines[3]
		result.B1.A1 = prodLines[4]

	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy034 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		pAcc[2], l0 = pr.doubleStep(pAcc[2])
		l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[2])
		l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[2])
		result = pr.Mul01234By034(&prodLines, &l0.R0, &l0.R1)

		// k >= 3
		for k := 3; k < n; k++ {
			pAcc[k], l0 = pr.doubleStep(pAcc[k])
			l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
			l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
			result = pr.MulBy034(result, &l0.R0, &l0.R1)
		}
	}

	// i = 187
	if n == 1 {
		result = pr.Square034(result)
	} else {
		result = pr.Square(result)
	}
	for k := 0; k < n; k++ {
		pAcc[k], l0 = pr.doubleStep(pAcc[k])
		l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
		l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
		result = pr.MulBy034(result, &l0.R0, &l0.R1)
	}

	for i := 186; i >= 1; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		j := loopCounterAlt2[i]*3 + loopCounterAlt1[i]

		for k := 0; k < n; k++ {
			switch j {
			case -4:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p01neg[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
				result = pr.MulBy034(result, &l01[k].R0, &l01[k].R1)
			case -3:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p1neg[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
			case -2:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p10[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
				result = pr.MulBy034(result, &l01[k].R0, &l01[k].R1)
			case -1:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p0neg[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
			case 0:
				pAcc[k], l0 = pr.doubleStep(pAcc[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				result = pr.MulBy034(result, &l0.R0, &l0.R1)
			case 1:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p0[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
			case 2:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p10neg[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
				result = pr.MulBy034(result, &l01[k].R0, &l01[k].R1)
			case 3:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p1[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
			case 4:
				pAcc[k], l0, l = pr.doubleAndAddStep(pAcc[k], p01[k])
				l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
				l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
				l.R0 = *pr.curveF.MulMod(&l.R0, xNegOverY[k])
				l.R1 = *pr.curveF.MulMod(&l.R1, yInv[k])
				prodLines = *pr.Mul034By034(&l0.R0, &l0.R1, &l.R0, &l.R1)
				result = pr.MulBy01234(result, &prodLines)
				result = pr.MulBy034(result, &l01[k].R0, &l01[k].R1)
			default:
				return nil, errors.New("invalid loopCounter")
			}
		}
	}

	// i = 0, j = -3
	// The resulting accumulator point is the infinity point because
	// [(x₀+1) + λ(x₀³-x₀²-x₀)]P = [3(x₀-1)² ⋅ r]P = ∞
	// since we're using affine coordinates, the addStep in the last iteration
	// (j=-3) will fail as the slope of a vertical line in indefinite. But in
	// projective coordinates, vertinal lines meet at (0:1:0) so the result
	// should be unchanged if we ommit the addStep in this case. Moreover we
	// just compute before the tangent line and not the full doubleStep as we
	// only care about the Miller loop result in Fp6 and not the point itself.
	result = pr.Square(result)
	for k := 0; k < n; k++ {
		l0 = pr.tangentCompute(pAcc[k])
		l0.R0 = *pr.curveF.MulMod(&l0.R0, xNegOverY[k])
		l0.R1 = *pr.curveF.MulMod(&l0.R1, yInv[k])
		result = pr.MulBy034(result, &l0.R0, &l0.R1)
	}

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

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *G1Affine) (*G1Affine, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p G1Affine

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
func (pr Pairing) doubleStep(p1 *G1Affine) (*G1Affine, *lineEvaluation) {

	var p G1Affine
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

// tangentCompute computes the line that goes through p1 and p2 but does not compute p1+p2
func (pr Pairing) tangentCompute(p1 *G1Affine) *lineEvaluation {

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	three := big.NewInt(3)
	n = pr.curveF.MulConst(n, three)
	d := pr.curveF.Add(&p1.Y, &p1.Y)
	λ := pr.curveF.Div(n, d)

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &line

}
