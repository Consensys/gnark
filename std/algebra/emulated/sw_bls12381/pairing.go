package sw_bls12381

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bls12381.Ext12
	*fields_bls12381.Ext2
	curveF *emulated.Field[BaseField]
	curve  *sw_emulated.Curve[BaseField, ScalarField]
	g2     *G2
	g1     *G1
	bTwist *fields_bls12381.E2
}

type baseEl = emulated.Element[BaseField]
type GTEl = fields_bls12381.E12

func NewGTEl(a bls12381.GT) GTEl {

	var c0, c1, c2, c3, c4, c5 fp.Element
	c0.Sub(&a.C0.B0.A0, &a.C0.B0.A1)
	c1.Sub(&a.C1.B0.A0, &a.C1.B0.A1)
	c2.Sub(&a.C0.B1.A0, &a.C0.B1.A1)
	c3.Sub(&a.C1.B1.A0, &a.C1.B1.A1)
	c4.Sub(&a.C0.B2.A0, &a.C0.B2.A1)
	c5.Sub(&a.C1.B2.A0, &a.C1.B2.A1)

	return GTEl{
		A0:  emulated.ValueOf[BaseField](c0),
		A1:  emulated.ValueOf[BaseField](c1),
		A2:  emulated.ValueOf[BaseField](c2),
		A3:  emulated.ValueOf[BaseField](c3),
		A4:  emulated.ValueOf[BaseField](c4),
		A5:  emulated.ValueOf[BaseField](c5),
		A6:  emulated.ValueOf[BaseField](a.C0.B0.A1),
		A7:  emulated.ValueOf[BaseField](a.C1.B0.A1),
		A8:  emulated.ValueOf[BaseField](a.C0.B1.A1),
		A9:  emulated.ValueOf[BaseField](a.C1.B1.A1),
		A10: emulated.ValueOf[BaseField](a.C0.B2.A1),
		A11: emulated.ValueOf[BaseField](a.C1.B2.A1),
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[BaseField, ScalarField](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	bTwist := fields_bls12381.E2{
		A0: emulated.ValueOf[BaseField]("4"),
		A1: emulated.ValueOf[BaseField]("4"),
	}
	g1, err := NewG1(api)
	if err != nil {
		return nil, fmt.Errorf("new G1 struct: %w", err)
	}
	return &Pairing{
		api:    api,
		Ext12:  fields_bls12381.NewExt12(api),
		Ext2:   fields_bls12381.NewExt2(api),
		curveF: ba,
		curve:  curve,
		g1:     g1,
		g2:     NewG2(api),
		bTwist: &bTwist,
	}, nil
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

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	f, err := pr.MillerLoop(P, Q)
	if err != nil {
		return err

	}

	pr.AssertFinalExponentiationIsOne(f)

	return nil
}

func (pr Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
}

func (pr Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
}

func (pr Pairing) AssertIsOnTwist(Q *G2Affine) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=4(1+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 4(1+u), and continue
	selector := pr.api.And(pr.Ext2.IsZero(&Q.P.X), pr.Ext2.IsZero(&Q.P.Y))
	b := pr.Ext2.Select(selector, pr.Ext2.Zero(), pr.bTwist)

	left := pr.Ext2.Square(&Q.P.Y)
	right := pr.Ext2.Square(&Q.P.X)
	right = pr.Ext2.Mul(right, &Q.P.X)
	right = pr.Ext2.Add(right, b)
	pr.Ext2.AssertIsEqual(left, right)
}

func (pr Pairing) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)

	// 2- Check P has the right subgroup order
	// [x²]ϕ(P)
	phiP := pr.g1.phi(P)
	_P := pr.g1.scalarMulBySeedSquare(phiP)
	_P = pr.curve.Neg(_P)

	// [r]Q == 0 <==>  P = -[x²]ϕ(P)
	pr.curve.AssertIsEqual(_P, P)
}

func (pr Pairing) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	pr.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	// [x₀]Q
	xQ := pr.g2.scalarMulBySeed(Q)
	// ψ(Q)
	psiQ := pr.g2.psi(Q)

	// [r]Q == 0 <==>  ψ(Q) == [x₀]Q
	pr.g2.AssertIsEqual(xQ, psiQ)
}

// loopCounter = seed in binary
//
//	seed=-15132376222941642752
var loopCounter = [64]int8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 0, 0, 1, 0, 1, 1,
}

// MillerLoop computes the multi-Miller loop
// ∏ᵢ { fᵢ_{u,Q}(P) }
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
		xNegOverY[k] = pr.curveF.MulMod(&P[k].X, yInv[k])
		xNegOverY[k] = pr.curveF.Neg(xNegOverY[k])
	}

	res := pr.Ext12.One()

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)
	for k := 0; k < n; k++ {
		res = pr.MulBy02368(res,
			pr.MulByElement(&lines[k][0][62].R1, yInv[k]),
			pr.MulByElement(&lines[k][0][62].R0, xNegOverY[k]),
		)
		res = pr.MulBy02368(res,
			pr.MulByElement(&lines[k][1][62].R1, yInv[k]),
			pr.MulByElement(&lines[k][1][62].R0, xNegOverY[k]),
		)
	}

	for i := 61; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res = pr.Ext12.Square(res)

		for k := 0; k < n; k++ {
			if loopCounter[i] == 0 {
				res = pr.MulBy02368(res,
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
				)
			} else {
				res = pr.MulBy02368(res,
					pr.MulByElement(&lines[k][0][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][0][i].R0, xNegOverY[k]),
				)
				res = pr.MulBy02368(res,
					pr.MulByElement(&lines[k][1][i].R1, yInv[k]),
					pr.MulByElement(&lines[k][1][i].R0, xNegOverY[k]),
				)
			}
		}
	}

	// negative x₀
	res = pr.Ext12.Conjugate(res)

	return res, nil
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 3 (Hayashida et al.)
func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	z := pr.Copy(e)

	// Easy part
	// (p⁶-1)(p²+1)
	t0 := pr.Ext12.Conjugate(z)
	t0 = pr.Ext12.DivUnchecked(t0, z)
	z = pr.Ext12.FrobeniusSquare(t0)
	z = pr.Ext12.Mul(z, t0)

	// Hard part (up to permutation)
	// Daiki Hayashida, Kenichiro Hayasaka and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	t0 = pr.Ext12.CyclotomicSquareGS(z)
	t1 := pr.Ext12.ExptHalfGS(t0)
	t2 := pr.Ext12.Conjugate(z)
	t1 = pr.Ext12.Mul(t1, t2)
	t2 = pr.Ext12.ExptGS(t1)
	t1 = pr.Ext12.Conjugate(t1)
	t1 = pr.Ext12.Mul(t1, t2)
	t2 = pr.Ext12.ExptGS(t1)
	t1 = pr.Ext12.Frobenius(t1)
	t1 = pr.Ext12.Mul(t1, t2)
	z = pr.Ext12.Mul(z, t0)
	t0 = pr.Ext12.ExptGS(t1)
	t2 = pr.Ext12.ExptGS(t0)
	t0 = pr.Ext12.FrobeniusSquare(t1)
	t1 = pr.Ext12.Conjugate(t1)
	t1 = pr.Ext12.Mul(t1, t2)
	t1 = pr.Ext12.Mul(t1, t0)
	z = pr.Ext12.Mul(z, t1)

	return z
}

// AssertFinalExponentiationIsOne checks that a Miller function output x lies in the
// same equivalence class as the reduced pairing. This replaces the final
// exponentiation step in-circuit.
// The method is inspired from [On Proving Pairings] paper by A. Novakovic and
// L. Eagen, and is based on a personal communication with A. Novakovic.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr Pairing) AssertFinalExponentiationIsOne(x *GTEl) {
	tower := pr.ToTower(x)

	res, err := pr.curveF.NewHint(finalExpHint, 24, tower[0], tower[1], tower[2], tower[3], tower[4], tower[5], tower[6], tower[7], tower[8], tower[9], tower[10], tower[11])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitness := pr.FromTower([12]*baseEl{res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7], res[8], res[9], res[10], res[11]})
	// constrain cubicNonResiduePower to be in Fp6
	// that is: a100=a101=a110=a111=a120=a121=0
	// or
	//     A0  =  a000 - a001
	//     A1  =  0
	//     A2  =  a010 - a011
	//     A3  =  0
	//     A4  =  a020 - a021
	//     A5  =  0
	//     A6  =  a001
	//     A7  =  0
	//     A8  =  a011
	//     A9  =  0
	//     A10 =  a021
	//     A11 =  0
	scalingFactor := GTEl{
		A0:  *pr.curveF.Sub(res[12], res[13]),
		A1:  *pr.curveF.Zero(),
		A2:  *pr.curveF.Sub(res[14], res[15]),
		A3:  *pr.curveF.Zero(),
		A4:  *pr.curveF.Sub(res[16], res[17]),
		A5:  *pr.curveF.Zero(),
		A6:  *res[13],
		A7:  *pr.curveF.Zero(),
		A8:  *res[15],
		A9:  *pr.curveF.Zero(),
		A10: *res[17],
		A11: *pr.curveF.Zero(),
	}

	// Check that  x * scalingFactor == residueWitness^(q-u)
	// where u=-0xd201000000010000 is the BLS12-381 seed,
	// and residueWitness, scalingFactor from the hint.
	t0 := pr.Frobenius(residueWitness)
	// exponentiation by -u
	t1 := pr.ExptNeg(residueWitness)
	t0 = pr.Ext12.Mul(t0, t1)

	t1 = pr.Ext12.Mul(x, &scalingFactor)

	pr.AssertIsEqual(t0, t1)
}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates.
// Then evaluates the lines going through p1 and p2 or -p2 (line1) and p1 and p1+p2 (line2).
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *g2AffP) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p g2AffP
	mone := pr.curveF.NewElement(-1)

	// compute λ1 = (y2-y1)/(x2-x1)
	n := pr.Ext2.Sub(&p1.Y, &p2.Y)
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	λ1 := pr.Ext2.DivUnchecked(n, d)

	// compute x3 =λ1²-x1-x2
	x30 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {mone, &λ1.A1, &λ1.A1}, {mone, &p1.X.A0}, {mone, &p2.X.A0}}, []int{1, 1, 1, 1})
	x31 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {mone, &p1.X.A1}, {mone, &p2.X.A1}}, []int{2, 1, 1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// omit y3 computation

	// compute line1
	line1.R0 = *λ1
	line1.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A0}, {mone, &λ1.A1, &p1.X.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	line1.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A1}, {&λ1.A1, &p1.X.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	d = pr.Ext2.Sub(x3, &p1.X)
	λ2 := pr.Ext2.DivUnchecked(n, d)
	λ2 = pr.Ext2.Add(λ2, λ1)
	λ2 = pr.Ext2.Neg(λ2)

	// compute x4 = λ2²-x1-x3
	x40 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &p1.X.A0}, {mone, x30}}, []int{1, 1, 1, 1})
	x41 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &p1.X.A1}, {mone, x31}}, []int{2, 1, 1})
	x4 := &fields_bls12381.E2{A0: *x40, A1: *x41}

	// compute y4 = λ2(x1 - x4)-y1
	y4 := pr.Ext2.Sub(&p1.X, x4)
	y40 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &y4.A0}, {mone, &λ2.A1, &y4.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	y41 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &y4.A1}, {&λ2.A1, &y4.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})
	y4 = &fields_bls12381.E2{A0: *y40, A1: *y41}

	p.X = *x4
	p.Y = *y4

	// compute line2
	line2.R0 = *λ2
	line2.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A0}, {mone, &λ2.A1, &p1.X.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	line2.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A1}, {&λ2.A1, &p1.X.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})

	return &p, &line1, &line2
}

// doubleStep doubles p1 in affine coordinates, and evaluates the tangent line to p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation) {

	var p g2AffP
	var line lineEvaluation
	mone := pr.curveF.NewElement(-1)

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	n = pr.Ext2.MulByConstElement(n, big.NewInt(3))
	d := pr.Ext2.MulByConstElement(&p1.Y, big.NewInt(2))
	λ := pr.Ext2.DivUnchecked(n, d)

	// xr = λ²-2x
	xr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {mone, &λ.A1, &λ.A1}, {mone, &p1.X.A0}}, []int{1, 1, 2})
	xr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {mone, &p1.X.A1}}, []int{2, 2})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x-xr)-y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr0 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {mone, &λ.A1, &yr.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	yr1 := pr.curveF.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	p.X = *xr
	p.Y = *yr

	line.R0 = *λ
	line.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A0}, {mone, &λ.A1, &p1.X.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	line.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A1}, {&λ.A1, &p1.X.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})

	return &p, &line

}

// tripleStep triples p1 in affine coordinates, and evaluates the line in Miller loop
func (pr Pairing) tripleStep(p1 *g2AffP) (*g2AffP, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var res g2AffP
	mone := pr.curveF.NewElement(-1)

	// λ1 = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	λ1 := pr.Ext2.DivUnchecked(n, d)

	// compute line1
	line1.R0 = *λ1
	line1.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A0}, {mone, &λ1.A1, &p1.X.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	line1.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ1.A0, &p1.X.A1}, {&λ1.A1, &p1.X.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})

	// x2 = λ1²-2x
	x20 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {mone, &λ1.A1, &λ1.A1}, {mone, &p1.X.A0}}, []int{1, 1, 2})
	x21 := pr.curveF.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {mone, &p1.X.A1}}, []int{2, 2})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit yr computation, and
	// compute λ2 = 2y/(x2 − x) − λ1.
	x1x2 := pr.Ext2.Sub(&p1.X, x2)
	λ2 := pr.Ext2.DivUnchecked(d, x1x2)
	λ2 = pr.Ext2.Sub(λ2, λ1)

	// compute line2
	line2.R0 = *λ2
	line2.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A0}, {mone, &λ2.A1, &p1.X.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	line2.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ2.A0, &p1.X.A1}, {&λ2.A1, &p1.X.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})

	// xr = λ²-x1-x2
	xr0 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &p1.X.A0}, {mone, x20}}, []int{1, 1, 1, 1})
	xr1 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &p1.X.A1}, {mone, x21}}, []int{2, 1, 1})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr) - y1
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr0 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &yr.A0}, {mone, &λ2.A1, &yr.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	yr1 := pr.curveF.Eval([][]*baseEl{{&λ2.A0, &yr.A1}, {&λ2.A1, &yr.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	res.X = *xr
	res.Y = *yr

	return &res, &line1, &line2
}

// tangentCompute computes the tangent line to p1, but does not compute [2]p1.
func (pr Pairing) tangentCompute(p1 *g2AffP) *lineEvaluation {

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	λ := pr.Ext2.DivUnchecked(n, d)

	var line lineEvaluation
	mone := pr.curveF.NewElement(-1)
	line.R0 = *λ
	line.R1.A0 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A0}, {mone, &λ.A1, &p1.X.A1}, {mone, &p1.Y.A0}}, []int{1, 1, 1})
	line.R1.A1 = *pr.curveF.Eval([][]*baseEl{{&λ.A0, &p1.X.A1}, {&λ.A1, &p1.X.A0}, {mone, &p1.Y.A1}}, []int{1, 1, 1})

	return &line

}
