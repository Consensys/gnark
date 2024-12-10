package sw_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fp_bn "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type baseEl = emulated.Element[BaseField]
type GTEl = fields_bn254.E12

type Pairing struct {
	api frontend.API
	*fields_bn254.Ext12
	*fields_bn254.Ext2
	curveF *emulated.Field[BaseField]
	curve  *sw_emulated.Curve[BaseField, ScalarField]
	g2     *G2
	bTwist *fields_bn254.E2
	g2gen  *G2Affine
}

func NewGTEl(a bn254.GT) GTEl {
	var c0, c1, c2, c3, c4, c5, t fp_bn.Element
	t.SetUint64(9).Mul(&t, &a.C0.B0.A1)
	c0.Sub(&a.C0.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B0.A1)
	c1.Sub(&a.C1.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B1.A1)
	c2.Sub(&a.C0.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B1.A1)
	c3.Sub(&a.C1.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B2.A1)
	c4.Sub(&a.C0.B2.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B2.A1)
	c5.Sub(&a.C1.B2.A0, &t)

	return GTEl{
		A0:  emulated.ValueOf[emulated.BN254Fp](c0),
		A1:  emulated.ValueOf[emulated.BN254Fp](c1),
		A2:  emulated.ValueOf[emulated.BN254Fp](c2),
		A3:  emulated.ValueOf[emulated.BN254Fp](c3),
		A4:  emulated.ValueOf[emulated.BN254Fp](c4),
		A5:  emulated.ValueOf[emulated.BN254Fp](c5),
		A6:  emulated.ValueOf[emulated.BN254Fp](a.C0.B0.A1),
		A7:  emulated.ValueOf[emulated.BN254Fp](a.C1.B0.A1),
		A8:  emulated.ValueOf[emulated.BN254Fp](a.C0.B1.A1),
		A9:  emulated.ValueOf[emulated.BN254Fp](a.C1.B1.A1),
		A10: emulated.ValueOf[emulated.BN254Fp](a.C0.B2.A1),
		A11: emulated.ValueOf[emulated.BN254Fp](a.C1.B2.A1),
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	bTwist := fields_bn254.E2{
		A0: emulated.ValueOf[BaseField]("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
		A1: emulated.ValueOf[BaseField]("266929791119991161246907387137283842545076965332900288569378510910307636690"),
	}
	return &Pairing{
		api:    api,
		Ext12:  fields_bn254.NewExt12(api),
		Ext2:   fields_bn254.NewExt2(api),
		curveF: ba,
		curve:  curve,
		g2:     NewG2(api),
		bTwist: &bTwist,
	}, nil
}

func (pr Pairing) generators() *G2Affine {
	if pr.g2gen == nil {
		_, _, _, g2gen := bn254.Generators()
		cg2gen := NewG2AffineFixed(g2gen)
		pr.g2gen = &cg2gen
	}
	return pr.g2gen
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroups. See AssertIsOnG1 and AssertIsOnG2.
func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.FinalExponentiation(res)
	return res, nil
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 2x₀(6x₀²+3x₀+1)
func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	// Easy part
	// (p⁶-1)(p²+1)
	t0 := pr.Ext12.Conjugate(e)
	e = pr.Ext12.Inverse(e)
	t0 = pr.Ext12.Mul(t0, e)
	e = pr.Ext12.FrobeniusSquare(t0)
	e = pr.Ext12.Mul(e, t0)

	// Hard part (up to permutation)
	// 2x₀(6x₀²+3x₀+1)(p⁴-p²+1)/r
	// Duquesne and Ghammam
	// https://eprint.iacr.org/2015/192.pdf
	// Fuentes et al. (alg. 6)
	t0 = pr.Ext12.Expt(e)
	t0 = pr.Ext12.Conjugate(t0)
	t0 = pr.Ext12.CyclotomicSquareGS(t0)
	t1 := pr.Ext12.CyclotomicSquareGS(t0)
	t1 = pr.Ext12.Mul(t0, t1)
	t2 := pr.Ext12.Expt(t1)
	t2 = pr.Ext12.Conjugate(t2)
	t3 := pr.Ext12.Conjugate(t1)
	t1 = pr.Ext12.Mul(t2, t3)
	t3 = pr.Ext12.CyclotomicSquareGS(t2)
	t4 := pr.Ext12.Expt(t3)
	t4 = pr.Ext12.Mul(t1, t4)
	t3 = pr.Ext12.Mul(t0, t4)
	t0 = pr.Ext12.Mul(t2, t4)
	t0 = pr.Ext12.Mul(e, t0)
	t2 = pr.Ext12.Frobenius(t3)
	t0 = pr.Ext12.Mul(t2, t0)
	t2 = pr.Ext12.FrobeniusSquare(t4)
	t0 = pr.Ext12.Mul(t2, t0)
	t2 = pr.Ext12.Conjugate(e)
	t2 = pr.Ext12.Mul(t2, t3)
	t2 = pr.Ext12.FrobeniusCube(t2)
	t0 = pr.Ext12.Mul(t2, t0)

	return t0
}

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups. See AssertIsOnG1 and AssertIsOnG2.
func (pr Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	f, err := pr.MillerLoop(P, Q)
	if err != nil {
		return err

	}

	pr.AssertFinalExponentiationIsOne(f)

	return nil
}

func (pr Pairing) IsEqual(x, y *GTEl) frontend.Variable {
	return pr.Ext12.IsEqual(x, y)
}

func (pr Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
}

func (pr Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
}

func (pr Pairing) computeTwistEquation(Q *G2Affine) (left, right *fields_bn254.E2) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=3/(9+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 3/(9+u), and continue
	selector := pr.api.And(pr.Ext2.IsZero(&Q.P.X), pr.Ext2.IsZero(&Q.P.Y))
	b := pr.Ext2.Select(selector, pr.Ext2.Zero(), pr.bTwist)

	left = pr.Ext2.Square(&Q.P.Y)
	right = pr.Ext2.Square(&Q.P.X)
	right = pr.Ext2.Mul(right, &Q.P.X)
	right = pr.Ext2.Add(right, b)
	return left, right
}

func (pr Pairing) AssertIsOnTwist(Q *G2Affine) {
	left, right := pr.computeTwistEquation(Q)
	pr.Ext2.AssertIsEqual(left, right)
}

// IsOnTwist returns a boolean indicating if the G2 point is in the twist.
func (pr Pairing) IsOnTwist(Q *G2Affine) frontend.Variable {
	left, right := pr.computeTwistEquation(Q)
	diff := pr.Ext2.Sub(left, right)
	return pr.Ext2.IsZero(diff)
}

func (pr Pairing) AssertIsOnG1(P *G1Affine) {
	// BN254 has a prime order, so we only
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)
}

func (pr Pairing) computeG2ShortVector(Q *G2Affine) (_Q *G2Affine) {
	// [x₀]Q
	xQ := pr.g2.scalarMulBySeed(Q)
	// ψ([x₀]Q)
	psixQ := pr.g2.psi(xQ)
	// ψ²([x₀]Q) = -ϕ([x₀]Q)
	psi2xQ := pr.g2.phi(xQ)
	// ψ³([2x₀]Q)
	psi3xxQ := pr.g2.double(psi2xQ)
	psi3xxQ = pr.g2.psi(psi3xxQ)

	// _Q = ψ³([2x₀]Q) - ψ²([x₀]Q) - ψ([x₀]Q) - [x₀]Q
	_Q = pr.g2.sub(psi2xQ, psi3xxQ)
	_Q = pr.g2.sub(_Q, psixQ)
	_Q = pr.g2.sub(_Q, xQ)
	return _Q
}

func (pr Pairing) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	pr.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	_Q := pr.computeG2ShortVector(Q)
	// [r]Q == 0 <==>  _Q == Q
	pr.g2.AssertIsEqual(Q, _Q)
}

// IsOnG2 returns a boolean indicating if the G2 point is in the subgroup. The
// method assumes that the point is already on the curve. Call
// [Pairing.AssertIsOnTwist] before to ensure point is on the curve.
func (pr Pairing) IsOnG2(Q *G2Affine) frontend.Variable {
	// 1 - is Q on curve
	isOnCurve := pr.IsOnTwist(Q)
	// 2 - is Q in the subgroup
	_Q := pr.computeG2ShortVector(Q)
	isInSubgroup := pr.g2.IsEqual(Q, _Q)
	return pr.api.And(isOnCurve, isInSubgroup)
}

// loopCounter = 6x₀+2 = 29793968203157093288
//
// in 2-NAF
var loopCounter = [66]int8{
	0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
	0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
	-1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
	-1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
}

// MillerLoop computes the multi-Miller loop
// ∏ᵢ { fᵢ_{6x₀+2,Q}(P) · ℓᵢ_{[6x₀+2]Q,π(Q)}(P) · ℓᵢ_{[6x₀+2]Q+π(Q),-π²(Q)}(P) }
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
	yInv := make([]*baseEl, n)
	xNegOverY := make([]*baseEl, n)

	for k := 0; k < n; k++ {
		// P are supposed to be on G1 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xNegOverY[k] = pr.curveF.Mul(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	var prodLines [10]*baseEl

	// Compute f_{6x₀+2,Q}(P)
	// i = 64
	//
	// k = 0
	c3 := pr.Ext2.MulByElement(&lines[0][0][64].R0, xNegOverY[0])
	c4 := pr.Ext2.MulByElement(&lines[0][0][64].R1, yInv[0])
	nine := big.NewInt(9)
	res := &GTEl{
		A0:  *pr.curveF.One(),
		A1:  *pr.curveF.Sub(&c3.A0, pr.curveF.MulConst(&c3.A1, nine)),
		A2:  *pr.curveF.Zero(),
		A3:  *pr.curveF.Sub(&c4.A0, pr.curveF.MulConst(&c4.A1, nine)),
		A4:  *pr.curveF.Zero(),
		A5:  *pr.curveF.Zero(),
		A6:  *pr.curveF.Zero(),
		A7:  c3.A1,
		A8:  *pr.curveF.Zero(),
		A9:  c4.A1,
		A10: *pr.curveF.Zero(),
		A11: *pr.curveF.Zero(),
	}

	if n >= 2 {
		for k := 1; k < n; k++ {
			// line evaluation at P[k]
			// ℓ × res
			res = pr.MulBy01379(
				res,
				pr.Ext2.MulByElement(&lines[k][0][64].R0, xNegOverY[k]),
				pr.Ext2.MulByElement(&lines[k][0][64].R1, yInv[k]),
			)

		}
	}

	for i := 63; i >= 0; i-- {
		res = pr.Ext12.Square(res)

		for k := 0; k < n; k++ {
			if loopCounter[i] == 0 {
				res = pr.MulBy01379(
					res,
					pr.Ext2.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][0][i].R1, yInv[k]),
				)
			} else {
				// ℓ × ℓ
				prodLines = pr.Mul01379By01379(
					pr.Ext2.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.Ext2.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
					pr.Ext2.MulByElement(&lines[k][1][i].R1, yInv[k]),
				)
				// (ℓ × ℓ) × res
				res = pr.Ext12.MulBy012346789(res, prodLines)
			}
		}
	}

	// Compute  ℓ_{[6x₀+2]Q,π(Q)}(P) · ℓ_{[6x₀+2]Q+π(Q),-π²(Q)}(P)
	// lines evaluations at P
	// and ℓ × ℓ
	for k := 0; k < n; k++ {
		prodLines = pr.Mul01379By01379(
			pr.Ext2.MulByElement(&lines[k][0][65].R0, xNegOverY[k]),
			pr.Ext2.MulByElement(&lines[k][0][65].R1, yInv[k]),
			pr.Ext2.MulByElement(&lines[k][1][65].R0, xNegOverY[k]),
			pr.Ext2.MulByElement(&lines[k][1][65].R1, yInv[k]),
		)
		res = pr.Ext12.MulBy012346789(res, prodLines)
	}

	return res, nil
}

// doubleAndAddStep doubles p1 and adds or subs p2 to the result in affine coordinates, based on the isSub boolean.
// Then evaluates the lines going through p1 and p2 or -p2 (line1) and p1 and p1+p2 or p1-p2 (line2).
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *g2AffP, isSub bool) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP

	// compute λ1 = (y1-y2)/(x1-x2) or λ1 = (y1+y2)/(x1-x2) if isSub is true
	var n *fields_bn254.E2
	if isSub {
		n = pr.Ext2.Add(&p1.Y, &p2.Y)
	} else {
		n = pr.Ext2.Sub(&p1.Y, &p2.Y)
	}
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	λ1 := pr.Ext2.DivUnchecked(n, d)

	// compute x3 =λ1²-x1-x2
	x3 := pr.Ext2.Square(λ1)
	x3 = pr.Ext2.Sub(x3, pr.Ext2.Add(&p1.X, &p2.X))

	// omit y3 computation

	// compute line1
	line1.R0 = *λ1
	line1.R1 = *pr.Ext2.Mul(λ1, &p1.X)
	line1.R1 = *pr.Ext2.Sub(&line1.R1, &p1.Y)

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	d = pr.Ext2.Sub(x3, &p1.X)
	λ2 := pr.Ext2.DivUnchecked(n, d)
	λ2 = pr.Ext2.Add(λ2, λ1)
	λ2 = pr.Ext2.Neg(λ2)

	// compute x4 = λ2²-x1-x3
	x4 := pr.Ext2.Square(λ2)
	x4 = pr.Ext2.Sub(x4, pr.Ext2.Add(&p1.X, x3))

	// compute y4 = λ2(x1 - x4)-y1
	y4 := pr.Ext2.Sub(&p1.X, x4)
	y4 = pr.Ext2.Mul(λ2, y4)
	y4 = pr.Ext2.Sub(y4, &p1.Y)

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *λ2
	line2.R1 = *pr.Ext2.Mul(λ2, &p1.X)
	line2.R1 = *pr.Ext2.Sub(&line2.R1, &p1.Y)

	return &p, &line1, &line2
}

// doubleStep doubles p1 in affine coordinates, and evaluates the tangent line to p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation) {

	var p g2AffP
	var line lineEvaluation

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	n = pr.Ext2.MulByConstElement(n, big.NewInt(3))
	d := pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	λ := pr.Ext2.DivUnchecked(n, d)

	// xr = λ²-2x
	xr := pr.Ext2.Square(λ)
	xr = pr.Ext2.Sub(xr, pr.Ext2.MulByConstElement(&p1.X, big.NewInt(2)))

	// yr = λ(x-xr)-y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr = pr.Ext2.Mul(λ, yr)
	yr = pr.Ext2.Sub(yr, &p1.Y)

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &p, &line

}

// addStep adds p1 and p2 in affine coordinates, and evaluates the line through p1 and p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) addStep(p1, p2 *g2AffP) (*g2AffP, *lineEvaluation) {

	// compute λ = (y2-y1)/(x2-x1)
	p2ypy := pr.Ext2.Sub(&p2.Y, &p1.Y)
	p2xpx := pr.Ext2.Sub(&p2.X, &p1.X)
	λ := pr.Ext2.DivUnchecked(p2ypy, p2xpx)

	// xr = λ²-x1-x2
	xr := pr.Ext2.Square(λ)
	xr = pr.Ext2.Sub(xr, pr.Ext2.Add(&p1.X, &p2.X))

	// yr = λ(x1-xr) - y1
	pxrx := pr.Ext2.Sub(&p1.X, xr)
	λpxrx := pr.Ext2.Mul(λ, pxrx)
	yr := pr.Ext2.Sub(λpxrx, &p1.Y)

	var res g2AffP
	res.X = *xr
	res.Y = *yr

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &res, &line

}

// lineCompute computes the line through p1 and p2, but does not compute p1+p2.
func (pr Pairing) lineCompute(p1, p2 *g2AffP) *lineEvaluation {

	// compute λ = (y2+y1)/(x2-x1)
	qypy := pr.Ext2.Add(&p1.Y, &p2.Y)
	qxpx := pr.Ext2.Sub(&p1.X, &p2.X)
	λ := pr.Ext2.DivUnchecked(qypy, qxpx)

	var line lineEvaluation
	line.R0 = *λ
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &line

}

// MillerLoopAndMul computes the Miller loop between P and Q
// and multiplies it in 𝔽p¹² by previous.
//
// This method is needed for evmprecompiles/ecpair.
func (pr Pairing) MillerLoopAndMul(P *G1Affine, Q *G2Affine, previous *GTEl) (*GTEl, error) {
	res, err := pr.MillerLoop([]*G1Affine{P}, []*G2Affine{Q})
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.Ext12.Mul(res, previous)
	return res, err
}

// millerLoopAndFinalExpResult computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and returns the result.
func (pr Pairing) millerLoopAndFinalExpResult(P *G1Affine, Q *G2Affine, previous *GTEl) *GTEl {
	nine := big.NewInt(9)
	a000 := pr.curveF.Add(&previous.A0, pr.curveF.MulConst(&previous.A6, nine))
	a001 := &previous.A6
	a010 := pr.curveF.Add(&previous.A2, pr.curveF.MulConst(&previous.A8, nine))
	a011 := &previous.A8
	a020 := pr.curveF.Add(&previous.A4, pr.curveF.MulConst(&previous.A10, nine))
	a021 := &previous.A10
	a100 := pr.curveF.Add(&previous.A1, pr.curveF.MulConst(&previous.A7, nine))
	a101 := &previous.A7
	a110 := pr.curveF.Add(&previous.A3, pr.curveF.MulConst(&previous.A9, nine))
	a111 := &previous.A9
	a120 := pr.curveF.Add(&previous.A5, pr.curveF.MulConst(&previous.A11, nine))
	a121 := &previous.A11

	// hint the non-residue witness
	hint, err := pr.curveF.NewHint(millerLoopAndCheckFinalExpHint, 18, &P.X, &P.Y, &Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1, a000, a001, a010, a011, a020, a021, a100, a101, a110, a111, a120, a121)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	residueWitness := GTEl{
		A0:  *pr.curveF.Sub(hint[0], pr.curveF.MulConst(hint[1], nine)),
		A1:  *pr.curveF.Sub(hint[6], pr.curveF.MulConst(hint[7], nine)),
		A2:  *pr.curveF.Sub(hint[2], pr.curveF.MulConst(hint[3], nine)),
		A3:  *pr.curveF.Sub(hint[8], pr.curveF.MulConst(hint[9], nine)),
		A4:  *pr.curveF.Sub(hint[4], pr.curveF.MulConst(hint[5], nine)),
		A5:  *pr.curveF.Sub(hint[10], pr.curveF.MulConst(hint[11], nine)),
		A6:  *hint[1],
		A7:  *hint[7],
		A8:  *hint[3],
		A9:  *hint[9],
		A10: *hint[5],
		A11: *hint[11],
	}

	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - 9 * a001
	//     A1  =  0
	//     A2  =  a010 - 9 * a011
	//     A3  =  0
	//     A4  =  a020 - 9 * a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	cubicNonResiduePower := GTEl{
		A0:  *pr.curveF.Sub(hint[12], pr.curveF.MulConst(hint[13], nine)),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(hint[14], pr.curveF.MulConst(hint[15], nine)),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(hint[16], pr.curveF.MulConst(hint[17], nine)),
		A5:  *pr.curveF.Zero(),
		A6:  *hint[13],
		A7:  *pr.curveF.Zero(),
		A8:  *hint[15],
		A9:  *pr.curveF.Zero(),
		A10: *hint[17],
		A11: *pr.curveF.Zero(),
	}

	// residueWitnessInv = 1 / residueWitness
	residueWitnessInv := pr.Ext12.Inverse(&residueWitness)

	if Q.Lines == nil {
		Qlines := pr.computeLines(&Q.P)
		Q.Lines = &Qlines
	}
	lines := *Q.Lines

	// precomputations
	yInv := pr.curveF.Inverse(&P.Y)
	xNegOverY := pr.curveF.Mul(&P.X, yInv)
	xNegOverY = pr.curveF.Neg(xNegOverY)

	// init Miller loop accumulator to residueWitnessInv to share the squarings
	// of residueWitnessInv^{6x₀+2}
	res := residueWitnessInv

	// Compute f_{6x₀+2,Q}(P)
	for i := 64; i >= 0; i-- {
		res = pr.Ext12.Square(res)

		switch loopCounter[i] {
		case 0:
			// ℓ × res
			res = pr.MulBy01379(
				res,
				pr.Ext2.MulByElement(&lines[0][i].R0, xNegOverY),
				pr.Ext2.MulByElement(&lines[0][i].R1, yInv),
			)
		case 1:
			// multiply by residueWitnessInv when bit=1
			res = pr.Ext12.Mul(res, residueWitnessInv)
			// lines evaluations at P
			// and ℓ × ℓ
			prodLines := pr.Mul01379By01379(
				pr.Ext2.MulByElement(&lines[0][i].R0, xNegOverY),
				pr.Ext2.MulByElement(&lines[0][i].R1, yInv),
				pr.Ext2.MulByElement(&lines[1][i].R0, xNegOverY),
				pr.Ext2.MulByElement(&lines[1][i].R1, yInv),
			)
			// (ℓ × ℓ) × res
			res = pr.Ext12.MulBy012346789(res, prodLines)
		case -1:
			// multiply by residueWitness when bit=-1
			res = pr.Ext12.Mul(res, &residueWitness)
			// lines evaluations at P
			// and ℓ × ℓ
			prodLines := pr.Mul01379By01379(
				pr.Ext2.MulByElement(&lines[0][i].R0, xNegOverY),
				pr.Ext2.MulByElement(&lines[0][i].R1, yInv),
				pr.Ext2.MulByElement(&lines[1][i].R0, xNegOverY),
				pr.Ext2.MulByElement(&lines[1][i].R1, yInv),
			)
			// (ℓ × ℓ) × res
			res = pr.Ext12.MulBy012346789(res, prodLines)
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}
	}

	// Compute  ℓ_{[6x₀+2]Q,π(Q)}(P) · ℓ_{[6x₀+2]Q+π(Q),-π²(Q)}(P)
	// lines evaluations at P
	prodLines := pr.Mul01379By01379(
		pr.Ext2.MulByElement(&lines[0][65].R0, xNegOverY),
		pr.Ext2.MulByElement(&lines[0][65].R1, yInv),
		pr.Ext2.MulByElement(&lines[1][65].R0, xNegOverY),
		pr.Ext2.MulByElement(&lines[1][65].R1, yInv),
	)
	res = pr.Ext12.MulBy012346789(res, prodLines)

	// multiply by previous multi-Miller function
	res = pr.Ext12.Mul(res, previous)

	// Check that  res * cubicNonResiduePower * residueWitnessInv^λ' == 1
	// where λ' = q^3 - q^2 + q, with u the BN254 seed
	// and residueWitnessInv, cubicNonResiduePower from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{6x₀+2} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	t2 := pr.Ext12.Mul(&cubicNonResiduePower, res)

	t1 := pr.FrobeniusCube(residueWitnessInv)
	t0 := pr.FrobeniusSquare(residueWitnessInv)
	t1 = pr.Ext12.DivUnchecked(t1, t0)
	t0 = pr.Frobenius(residueWitnessInv)
	t1 = pr.Ext12.Mul(t1, t0)

	t2 = pr.Ext12.Mul(t2, t1)

	return t2
}

// IsMillerLoopAndFinalExpOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and and returns a boolean indicating if
// the result lies in the same equivalence class as the reduced pairing
// purported to be 1. This check replaces the final exponentiation step
// in-circuit and follows Section 4 of [On Proving Pairings] paper by A.
// Novakovic and L. Eagen.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr Pairing) IsMillerLoopAndFinalExpOne(P *G1Affine, Q *G2Affine, previous *GTEl) frontend.Variable {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)

	res := pr.IsEqual(t2, pr.Ext12.One())
	return res
}

// AssertMillerLoopAndFinalExpIsOne computes the Miller loop between P and Q,
// multiplies it in 𝔽p¹² by previous and checks that the result lies in the
// same equivalence class as the reduced pairing purported to be 1. This check
// replaces the final exponentiation step in-circuit and follows Section 4 of
// [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// This method is needed for evmprecompiles/ecpair.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr Pairing) AssertMillerLoopAndFinalExpIsOne(P *G1Affine, Q *G2Affine, previous *GTEl) {
	t2 := pr.millerLoopAndFinalExpResult(P, Q, previous)
	pr.AssertIsEqual(t2, pr.Ext12.One())
}
