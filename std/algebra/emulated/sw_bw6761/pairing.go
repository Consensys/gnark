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
// where s is the cofactor (x₀+1)
func (pr Pairing) FinalExponentiation(z *GTEl) *GTEl {

	z = pr.Reduce(z)
	result := pr.Copy(z)

	// 1. Easy part
	// (p³-1)(p+1)
	buf := pr.Conjugate(result)
	buf = pr.DivUnchecked(buf, result)
	result = pr.Frobenius(buf)
	result = pr.Mul(result, buf)

	// 2. Hard part (up to permutation)
	// (x₀+1)(p²-p+1)/r
	// Algorithm 4.4 from https://yelhousni.github.io/phd.pdf
	a := pr.ExpX0Minus1Square(result)
	a = pr.Mul(a, pr.Frobenius(result))
	b := pr.ExpX0Plus1(a)
	b = pr.Mul(b, pr.Conjugate(result))
	t := pr.CyclotomicSquare(a)
	a = pr.Mul(a, t)
	c := pr.ExptMinus1Div3(b)
	d := pr.ExpX0Minus1(c)
	e := pr.ExpX0Minus1Square(d)
	e = pr.Mul(e, d)
	d = pr.Conjugate(d)
	f := pr.Mul(d, b)
	g := pr.ExpX0Plus1(e)
	g = pr.Mul(g, f)
	h := pr.Mul(g, c)
	i := pr.Mul(g, d)
	i = pr.ExpX0Plus1(i)
	i = pr.Mul(i, pr.Conjugate(f))
	j := pr.ExpC1(h)
	j = pr.Mul(j, e)
	k := pr.CyclotomicSquare(j)
	k = pr.Mul(k, j)
	k = pr.Mul(k, b)
	t = pr.ExpC2(i)
	k = pr.Mul(k, t)
	result = pr.Mul(a, k)

	return result
}

// LineEvaluation represents a sparse Fp6 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014)
type LineEvaluation struct {
	R0, R1 emulated.Element[emulated.BW6761Fp]
}

// NewLineEvaluation allocates a witness from the native LineEvaluationAff and returns it.
func NewLineEvaluation(v bw6761.LineEvaluationAff) LineEvaluation {
	return LineEvaluation{
		R0: emulated.ValueOf[emulated.BW6761Fp](v.R0),
		R1: emulated.ValueOf[emulated.BW6761Fp](v.R1),
	}
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
var loopCounter1 = [190]int8{
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
var loopCounter2 = [190]int8{
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
var thirdRootOne = emulated.ValueOf[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")

// MillerLoop computes the optimal Tate multi-Miller loop
// (or twisted ate or Eta revisited)
//
// ∏ᵢ { fᵢ_{x₀+1+λ(x₀³-x₀²-x₀),Qᵢ}(Pᵢ) }
//
// Alg.2 in https://eprint.iacr.org/2021/1359.pdf
// Eq. (6') in https://hackmd.io/@gnark/BW6-761-changes
func (pr Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations
	negQ := make([]*G2Affine, n)
	imQ := make([]*G2Affine, n)
	imQneg := make([]*G2Affine, n)
	accQ := make([]*G2Affine, n)
	yInv := make([]*emulated.Element[emulated.BW6761Fp], n)
	xNegOverY := make([]*emulated.Element[emulated.BW6761Fp], n)

	for k := 0; k < n; k++ {
		// P and Q are supposed to be on G1 and G2 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xNegOverY[k] = pr.curveF.MulMod(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
		// negQ = -Q = (x, -y)
		negQ[k] = &G1Affine{X: Q[k].X, Y: *pr.curveF.Neg(&Q[k].Y)}
		// imQ = (w*x, -y)
		imQ[k] = &G1Affine{X: *pr.curveF.MulMod(&Q[k].X, &thirdRootOne), Y: negQ[k].Y}
		// imQneg = (w*x, y)
		imQneg[k] = &G1Affine{X: imQ[k].X, Y: Q[k].Y}
		// point accumulator initialized to imQ
		accQ[k] = imQ[k]
	}

	// f_{x₀+1+λ(x₀³-x₀²-x₀),Q}(P)
	result := pr.Ext6.One()
	var l0, l1 *LineEvaluation

	var prodLines [5]*emulated.Element[emulated.BW6761Fp]
	// i = 188, separately to avoid an E6 Square
	// (Square(res) = 1² = 1)
	// k = 0, separately to avoid MulBy014 (res × ℓ)
	// (assign line to res)
	accQ[0], l0 = pr.doubleStep(imQ[0])
	result = &fields_bw6761.E6{
		B0: fields_bw6761.E3{
			A0: *pr.curveF.MulMod(&l0.R1, yInv[0]),
			A1: *pr.curveF.MulMod(&l0.R0, xNegOverY[0]),
			A2: result.B0.A2,
		},
		B1: fields_bw6761.E3{
			A0: result.B1.A0,
			A1: *pr.curveF.One(),
			A2: result.B1.A2,
		},
	}

	if n >= 2 {
		// k = 1, separately to avoid MulBy014 (res × ℓ)
		// (res is also a line at this point, so we use Mul014By014 ℓ × ℓ)
		accQ[1], l0 = pr.doubleStep(accQ[1])
		l0 = &LineEvaluation{
			R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[1]),
			R1: *pr.curveF.MulMod(&l0.R1, yInv[1]),
		}
		prodLines = pr.Mul014By014(&l0.R1, &l0.R0, &result.B0.A0, &result.B0.A1)
		result = &fields_bw6761.E6{
			B0: fields_bw6761.E3{
				A0: *prodLines[0],
				A1: *prodLines[1],
				A2: *prodLines[2],
			},
			B1: fields_bw6761.E3{
				A0: result.B1.A0,
				A1: *prodLines[3],
				A2: *prodLines[4],
			},
		}
	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy014 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		accQ[2], l0 = pr.doubleStep(accQ[2])
		l0 = &LineEvaluation{
			R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[2]),
			R1: *pr.curveF.MulMod(&l0.R1, yInv[2]),
		}
		result = pr.Mul01245By014(prodLines, &l0.R1, &l0.R0)

		// k >= 3
		for k := 3; k < n; k++ {
			accQ[k], l0 = pr.doubleStep(accQ[k])
			l0 = &LineEvaluation{
				R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
				R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
			}
			result = pr.MulBy014(result, &l0.R1, &l0.R0)
		}
	}

	for i := 187; i >= 1; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		j := loopCounter2[i]*3 + loopCounter1[i]

		for k := 0; k < n; k++ {
			switch j {
			// cases -4, -2, 2 and 4 are omitted as they do not occur given the
			// static loop counters.
			case -3:
				accQ[k], l0, l1 = pr.doubleAndAddStep(accQ[k], imQneg[k])
				l0 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l0.R1, &l0.R0)
				l1 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l1.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l1.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l1.R1, &l1.R0)
			case -1:
				accQ[k], l0, l1 = pr.doubleAndAddStep(accQ[k], negQ[k])
				l0 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l0.R1, &l0.R0)
				l1 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l1.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l1.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l1.R1, &l1.R0)
			case 0:
				accQ[k], l0 = pr.doubleStep(accQ[k])
				l0 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l0.R1, &l0.R0)
			case 1:
				accQ[k], l0, l1 = pr.doubleAndAddStep(accQ[k], Q[k])
				l0 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l0.R1, &l0.R0)
				l1 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l1.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l1.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l1.R1, &l1.R0)
			case 3:
				accQ[k], l0, l1 = pr.doubleAndAddStep(accQ[k], imQ[k])
				l0 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l0.R1, &l0.R0)
				l1 = &LineEvaluation{
					R0: *pr.curveF.MulMod(&l1.R0, xNegOverY[k]),
					R1: *pr.curveF.MulMod(&l1.R1, yInv[k]),
				}
				result = pr.MulBy014(result, &l1.R1, &l1.R0)
			default:
				return nil, errors.New("invalid loopCounter")
			}
		}
	}

	// i = 0, j = -3
	// The resulting accumulator point is the infinity point because
	// [(x₀+1) + λ(x₀³-x₀²-x₀)]Q = [3(x₀-1)² ⋅ r]Q = ∞
	// since we're using affine coordinates, the addStep in the last iteration
	// (j=-3) will fail as the slope of a vertical line in indefinite. But in
	// projective coordinates, vertinal lines meet at (0:1:0) so the result
	// should be unchanged if we ommit the addStep in this case. Moreover we
	// just compute before the tangent line and not the full doubleStep as we
	// only care about the Miller loop result in Fp6 and not the point itself.
	result = pr.Square(result)
	for k := 0; k < n; k++ {
		l0 = pr.tangentCompute(accQ[k])
		l0 = &LineEvaluation{
			R0: *pr.curveF.MulMod(&l0.R0, xNegOverY[k]),
			R1: *pr.curveF.MulMod(&l0.R1, yInv[k]),
		}
		result = pr.MulBy014(result, &l0.R1, &l0.R0)
	}

	return result, nil

}

// addStep adds two points in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) addStep(p1, p2 *G2Affine) (*G2Affine, *LineEvaluation) {

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

	var line LineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &res, &line

}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *G2Affine) (*G2Affine, *LineEvaluation, *LineEvaluation) {

	var line1, line2 LineEvaluation
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
func (pr Pairing) doubleStep(p1 *G2Affine) (*G2Affine, *LineEvaluation) {

	var p G2Affine
	var line LineEvaluation

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
func (pr Pairing) tangentCompute(p1 *G2Affine) *LineEvaluation {

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	three := big.NewInt(3)
	n = pr.curveF.MulConst(n, three)
	d := pr.curveF.Add(&p1.Y, &p1.Y)
	λ := pr.curveF.Div(n, d)

	var line LineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &line

}

// ----------------------------
//	  Fixed-argument pairing
// ----------------------------

// MillerLoopFixedQ computes the multi-Miller loop as in MillerLoop
// but Qᵢ are fixed points in G2 known in advance.
func (pr Pairing) MillerLoopFixedQ(P []*G1Affine, lines [][2][189]LineEvaluation) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(lines) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations
	yInv := make([]*emulated.Element[emulated.BW6761Fp], n)
	xNegOverY := make([]*emulated.Element[emulated.BW6761Fp], n)

	for k := 0; k < n; k++ {
		// P are supposed to be on G1 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xNegOverY[k] = pr.curveF.MulMod(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	// f_{x₀+1+λ(x₀³-x₀²-x₀),Q}(P), Q is known in advance
	var prodLines [5]*emulated.Element[emulated.BW6761Fp]
	result := pr.Ext6.One()

	// i = 188
	// k = 0
	result = &fields_bw6761.E6{
		B0: fields_bw6761.E3{
			A0: *pr.curveF.MulMod(&lines[0][0][188].R1, yInv[0]),
			A1: *pr.curveF.MulMod(&lines[0][0][188].R0, xNegOverY[0]),
			A2: result.B0.A2,
		},
		B1: fields_bw6761.E3{
			A0: result.B1.A0,
			A1: *pr.curveF.One(),
			A2: result.B1.A2,
		},
	}

	if n >= 2 {
		// k = 1, separately to avoid MulBy014 (res × ℓ)
		// (res is also a line at this point, so we use Mul014By014 ℓ × ℓ)
		prodLines = pr.Mul014By014(
			pr.curveF.MulMod(&lines[1][0][188].R1, yInv[1]),
			pr.curveF.MulMod(&lines[1][0][188].R0, xNegOverY[1]),
			&result.B0.A0,
			&result.B0.A1,
		)
		result = &fields_bw6761.E6{
			B0: fields_bw6761.E3{
				A0: *prodLines[0],
				A1: *prodLines[1],
				A2: *prodLines[2],
			},
			B1: fields_bw6761.E3{
				A0: result.B1.A0,
				A1: *prodLines[3],
				A2: *prodLines[4],
			},
		}
	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy014 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		result = pr.Mul01245By014(
			prodLines,
			pr.curveF.MulMod(&lines[2][0][188].R1, yInv[2]),
			pr.curveF.MulMod(&lines[2][0][188].R0, xNegOverY[2]),
		)

		// k >= 3
		for k := 3; k < n; k++ {
			result = pr.MulBy014(result,
				pr.curveF.MulMod(&lines[k][0][188].R1, yInv[k]),
				pr.curveF.MulMod(&lines[k][0][188].R0, xNegOverY[k]),
			)
		}
	}

	for i := 187; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		for k := 0; k < n; k++ {
			result = pr.MulBy014(result,
				pr.curveF.MulMod(&lines[k][0][i].R1, yInv[k]),
				pr.curveF.MulMod(&lines[k][0][i].R0, xNegOverY[k]),
			)
		}

		if loopCounter2[i]*3+loopCounter1[i] != 0 {
			for k := 0; k < n; k++ {
				result = pr.MulBy014(result,
					pr.curveF.MulMod(&lines[k][1][i].R1, yInv[k]),
					pr.curveF.MulMod(&lines[k][1][i].R0, xNegOverY[k]),
				)
			}
		}
	}

	return result, nil

}

// PairFixedQ calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ) where Qᵢ are fixed points known in advance.
//
// This function doesn't check that the inputs are in the correct subgroup. See IsInSubGroup.
func (pr Pairing) PairFixedQ(P []*G1Affine, lines [][2][189]LineEvaluation) (*GTEl, error) {
	f, err := pr.MillerLoopFixedQ(P, lines)
	if err != nil {
		return nil, err
	}
	return pr.FinalExponentiation(f), nil
}

// PairingFixedQCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1 where Qᵢ are fixed points known in advance.
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr Pairing) PairingFixedQCheck(P []*G1Affine, lines [][2][189]LineEvaluation) error {
	f, err := pr.PairFixedQ(P, lines)
	if err != nil {
		return err

	}
	one := pr.One()
	pr.AssertIsEqual(f, one)

	return nil
}
