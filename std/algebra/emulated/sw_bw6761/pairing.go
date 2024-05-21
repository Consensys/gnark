package sw_bw6761

import (
	"errors"
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bw6761.Ext6
	curveF *emulated.Field[BaseField]
	curve  *sw_emulated.Curve[BaseField, ScalarField]
	g1     *G1
	g2     *G2
	g2gen  *G2Affine
}

type GTEl = fields_bw6761.E6

func NewGTEl(v bw6761.GT) GTEl {
	return GTEl{
		A0: emulated.ValueOf[BaseField](v.B0.A0),
		A1: emulated.ValueOf[BaseField](v.B1.A0),
		A2: emulated.ValueOf[BaseField](v.B0.A1),
		A3: emulated.ValueOf[BaseField](v.B1.A1),
		A4: emulated.ValueOf[BaseField](v.B0.A2),
		A5: emulated.ValueOf[BaseField](v.B1.A2),
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBW6761Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	g1, err := NewG1(api)
	if err != nil {
		return nil, fmt.Errorf("new G1 struct: %w", err)
	}
	g2, err := NewG2(api)
	if err != nil {
		return nil, fmt.Errorf("new G2 struct: %w", err)
	}
	return &Pairing{
		api:    api,
		Ext6:   fields_bw6761.NewExt6(api),
		curveF: ba,
		curve:  curve,
		g1:     g1,
		g2:     g2,
	}, nil
}

func (pr Pairing) generators() *G2Affine {
	if pr.g2gen == nil {
		_, _, _, g2gen := bw6761.Generators()
		cg2gen := NewG2AffineFixed(g2gen)
		pr.g2gen = &cg2gen
	}
	return pr.g2gen
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
	t := pr.CyclotomicSquareKarabina12345(a)
	t = pr.DecompressKarabina12345(t)
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
	k := pr.CyclotomicSquareKarabina12345(j)
	k = pr.DecompressKarabina12345(k)
	k = pr.Mul(k, j)
	k = pr.Mul(k, b)
	t = pr.ExpC2(i)
	k = pr.Mul(k, t)
	result = pr.Mul(a, k)

	return result
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

func (pr Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
}

func (pr Pairing) AssertIsOnTwist(Q *G2Affine) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=4
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 4, and continue
	selector := pr.api.And(pr.curveF.IsZero(&Q.P.X), pr.curveF.IsZero(&Q.P.Y))
	bTwist := emulated.ValueOf[BaseField](4)
	b := pr.curveF.Select(selector, pr.curveF.Zero(), &bTwist)

	left := pr.curveF.Mul(&Q.P.Y, &Q.P.Y)
	right := pr.curveF.Mul(&Q.P.X, &Q.P.X)
	right = pr.curveF.Mul(right, &Q.P.X)
	right = pr.curveF.Add(right, b)
	pr.curveF.AssertIsEqual(left, right)
}

func (pr Pairing) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)

	// 2- Check P has the right subgroup order
	// we check that [x₀+1]P == [-x₀³+x₀²-1]ϕ(P)
	xP := pr.g1.scalarMulBySeed(P)
	x2P := pr.g1.scalarMulBySeed(xP)
	x3P := pr.g1.scalarMulBySeed(x2P)

	left := pr.g1.add(xP, P)
	right := pr.g1.sub(x2P, x3P)
	right = pr.g1.sub(right, P)
	right = pr.g1.phi(right)

	// [r]P == 0 <==> [x₀+1]P == [-x₀³+x₀²-1]ϕ(P)
	pr.curve.AssertIsEqual(left, right)
}

func (pr Pairing) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	pr.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	// we check that [x₀+1]Q == [-x₀³+x₀²-1]ϕ(Q)
	xQ := pr.g2.scalarMulBySeed(Q)
	x2Q := pr.g2.scalarMulBySeed(xQ)
	x3Q := pr.g2.scalarMulBySeed(x2Q)

	left := pr.g2.add(xQ, Q)
	right := pr.g2.sub(x2Q, x3Q)
	right = pr.g2.sub(right, Q)
	right = pr.g2.phi(right)

	// [r]Q == 0 <==> [x₀+1]Q == [-x₀³+x₀²-1]ϕ(Q)
	pr.g2.AssertIsEqual(left, right)
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
var thirdRootOne = emulated.ValueOf[BaseField]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")

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
	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := pr.computeLines(&Q[i].P)
			Q[i].Lines = &Qlines
		}
		lines[i] = *Q[i].Lines
	}
	return pr.millerLoopLines(P, lines)

}

// millerLoopLines computes the multi-Miller loop from points in G1 and precomputed lines in G2
func (pr Pairing) millerLoopLines(P []*G1Affine, lines []lineEvaluations) (*GTEl, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(lines) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations
	yInv := make([]*emulated.Element[BaseField], n)
	xNegOverY := make([]*emulated.Element[BaseField], n)

	for k := 0; k < n; k++ {
		// P are supposed to be on G1 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xNegOverY[k] = pr.curveF.Mul(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	// f_{x₀+1+λ(x₀³-x₀²-x₀),Q}(P), Q is known in advance
	var prodLines [5]*emulated.Element[BaseField]
	result := pr.Ext6.One()

	// i = 188
	// k = 0
	result = &fields_bw6761.E6{
		A0: *pr.curveF.Mul(&lines[0][0][188].R1, yInv[0]),
		A1: result.A1,
		A2: *pr.curveF.Mul(&lines[0][0][188].R0, xNegOverY[0]),
		A3: *pr.curveF.One(),
		A4: result.A4,
		A5: result.A5,
	}

	if n >= 2 {
		// k = 1, separately to avoid MulBy023 (res × ℓ)
		// (res is also a line at this point, so we use Mul023By023 ℓ × ℓ)
		prodLines = pr.Mul023By023(
			pr.curveF.Mul(&lines[1][0][188].R1, yInv[1]),
			pr.curveF.Mul(&lines[1][0][188].R0, xNegOverY[1]),
			&result.A0,
			&result.A2,
		)
		result = &fields_bw6761.E6{
			A0: *prodLines[0],
			A1: result.A1,
			A2: *prodLines[1],
			A3: *prodLines[2],
			A4: *prodLines[3],
			A5: *prodLines[4],
		}
	}

	for k := 2; k < n; k++ {
		result = pr.MulBy023(result,
			pr.curveF.Mul(&lines[k][0][188].R1, yInv[k]),
			pr.curveF.Mul(&lines[k][0][188].R0, xNegOverY[k]),
		)
	}

	for i := 187; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		if i > 0 && loopCounter2[i]*3+loopCounter1[i] != 0 {
			for k := 0; k < n; k++ {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k][1][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][1][i].R0, xNegOverY[k]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
		} else {
			// if number of lines is odd, mul last line by res
			// works for n=1 as well
			if n%2 != 0 {
				// ℓ × res
				result = pr.MulBy023(result,
					pr.curveF.Mul(&lines[n-1][0][i].R1, yInv[n-1]),
					pr.curveF.Mul(&lines[n-1][0][i].R0, xNegOverY[n-1]),
				)
			}
			// mul lines 2-by-2
			for k := 1; k < n; k += 2 {
				prodLines = pr.Mul023By023(
					pr.curveF.Mul(&lines[k][0][i].R1, yInv[k]),
					pr.curveF.Mul(&lines[k][0][i].R0, xNegOverY[k]),
					pr.curveF.Mul(&lines[k-1][0][i].R1, yInv[k-1]),
					pr.curveF.Mul(&lines[k-1][0][i].R0, xNegOverY[k-1]),
				)
				result = pr.MulBy02345(result, prodLines)
			}
		}
	}

	return result, nil

}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *g2AffP) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP

	// compute λ1 = (y2-y1)/(x2-x1)
	n := pr.curveF.Sub(&p1.Y, &p2.Y)
	d := pr.curveF.Sub(&p1.X, &p2.X)
	l1 := pr.curveF.Div(n, d)

	// compute x3 =λ1²-x1-x2
	x3 := pr.curveF.Mul(l1, l1)
	x3 = pr.curveF.Sub(x3, pr.curveF.Add(&p1.X, &p2.X))

	// omit y3 computation

	// compute line1
	line1.R0 = *l1
	line1.R1 = *pr.curveF.Mul(l1, &p1.X)
	line1.R1 = *pr.curveF.Sub(&line1.R1, &p1.Y)

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.curveF.MulConst(&p1.Y, big.NewInt(2))
	d = pr.curveF.Sub(&p1.X, x3)
	l2 := pr.curveF.Div(n, d)
	l2 = pr.curveF.Sub(l2, l1)

	// compute x4 = λ2²-x1-x3
	x4 := pr.curveF.Mul(l2, l2)
	x4 = pr.curveF.Sub(x4, pr.curveF.Add(&p1.X, x3))

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
func (pr Pairing) doubleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation) {

	var p g2AffP
	var line lineEvaluation

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	n = pr.curveF.MulConst(n, big.NewInt(3))
	d := pr.curveF.MulConst(&p1.Y, big.NewInt(2))
	λ := pr.curveF.Div(n, d)

	// xr = λ²-2x
	xr := pr.curveF.Mul(λ, λ)
	xr = pr.curveF.Sub(xr, pr.curveF.MulConst(&p1.X, big.NewInt(2)))

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
func (pr Pairing) tangentCompute(p1 *g2AffP) *lineEvaluation {

	// λ = 3x²/2y
	n := pr.curveF.Mul(&p1.X, &p1.X)
	n = pr.curveF.MulConst(n, big.NewInt(3))
	d := pr.curveF.MulConst(&p1.Y, big.NewInt(2))
	λ := pr.curveF.Div(n, d)

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.curveF.Mul(λ, &p1.X)
	line.R1 = *pr.curveF.Sub(&line.R1, &p1.Y)

	return &line

}
