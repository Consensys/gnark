package sw_bls12381

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	api frontend.API
	*fields_bls12381.Ext12
	curveF *emulated.Field[emulated.BLS12381Fp]
	g2     *G2
	g1     *G1
	curve  *sw_emulated.Curve[emulated.BLS12381Fp, emulated.BLS12381Fr]
	bTwist *fields_bls12381.E2
}

type GTEl = fields_bls12381.E12

func NewGTEl(v bls12381.GT) GTEl {
	return GTEl{
		C0: fields_bls12381.E6{
			B0: fields_bls12381.E2{
				A0: emulated.ValueOf[emulated.BLS12381Fp](v.C0.B0.A0),
				A1: emulated.ValueOf[emulated.BLS12381Fp](v.C0.B0.A1),
			},
			B1: fields_bls12381.E2{
				A0: emulated.ValueOf[emulated.BLS12381Fp](v.C0.B1.A0),
				A1: emulated.ValueOf[emulated.BLS12381Fp](v.C0.B1.A1),
			},
			B2: fields_bls12381.E2{
				A0: emulated.ValueOf[emulated.BLS12381Fp](v.C0.B2.A0),
				A1: emulated.ValueOf[emulated.BLS12381Fp](v.C0.B2.A1),
			},
		},
		C1: fields_bls12381.E6{
			B0: fields_bls12381.E2{
				A0: emulated.ValueOf[emulated.BLS12381Fp](v.C1.B0.A0),
				A1: emulated.ValueOf[emulated.BLS12381Fp](v.C1.B0.A1),
			},
			B1: fields_bls12381.E2{
				A0: emulated.ValueOf[emulated.BLS12381Fp](v.C1.B1.A0),
				A1: emulated.ValueOf[emulated.BLS12381Fp](v.C1.B1.A1),
			},
			B2: fields_bls12381.E2{
				A0: emulated.ValueOf[emulated.BLS12381Fp](v.C1.B2.A0),
				A1: emulated.ValueOf[emulated.BLS12381Fp](v.C1.B2.A1),
			},
		},
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	bTwist := fields_bls12381.E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp]("4"),
		A1: emulated.ValueOf[emulated.BLS12381Fp]("4"),
	}
	g1, err := NewG1(api)
	if err != nil {
		return nil, fmt.Errorf("new G1 struct: %w", err)
	}
	return &Pairing{
		api:    api,
		Ext12:  fields_bls12381.NewExt12(api),
		curveF: ba,
		curve:  curve,
		g1:     g1,
		g2:     NewG2(api),
		bTwist: &bTwist,
	}, nil
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
//
// we use instead
//
//	d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
//
// where s is the cofactor 3 (Hayashida et al.).
//
// This is the safe version of the method where e may be {-1,1}. If it is known
// that e ≠ {-1,1} then using the unsafe version of the method saves
// considerable amount of constraints. When called with the result of
// [MillerLoop], then current method is applicable when length of the inputs to
// Miller loop is 1.
func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	return pr.finalExponentiation(e, false)
}

// FinalExponentiationUnsafe computes the exponentiation (∏ᵢ zᵢ)ᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
//
// we use instead
//
//	d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
//
// where s is the cofactor 3 (Hayashida et al.).
//
// This is the unsafe version of the method where e may NOT be {-1,1}. If e ∈
// {-1, 1}, then there exists no valid solution to the circuit. This method is
// applicable when called with the result of [MillerLoop] method when the length
// of the inputs to Miller loop is 1.
func (pr Pairing) FinalExponentiationUnsafe(e *GTEl) *GTEl {
	return pr.finalExponentiation(e, true)
}

// finalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ where
//
//	d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
//
// we use instead
//
//	d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
//
// where s is the cofactor 3 (Hayashida et al.).
func (pr Pairing) finalExponentiation(e *GTEl, unsafe bool) *GTEl {

	// 1. Easy part
	// (p⁶-1)(p²+1)
	var selector1, selector2 frontend.Variable
	_dummy := pr.Ext6.One()

	if unsafe {
		// The Miller loop result is ≠ {-1,1}, otherwise this means P and Q are
		// linearly dependant and not from G1 and G2 respectively.
		// So e ∈ G_{q,2} \ {-1,1} and hence e.C1 ≠ 0.
		// Nothing to do.
	} else {
		// However, for a product of Miller loops (n>=2) this might happen.  If this is
		// the case, the result is 1 in the torus. We assign a dummy value (1) to e.C1
		// and proceed further.
		selector1 = pr.Ext6.IsZero(&e.C1)
		e.C1 = *pr.Ext6.Select(selector1, _dummy, &e.C1)
	}

	// Torus compression absorbed:
	// Raising e to (p⁶-1) is
	// e^(p⁶) / e = (e.C0 - w*e.C1) / (e.C0 + w*e.C1)
	//            = (-e.C0/e.C1 + w) / (-e.C0/e.C1 - w)
	// So the fraction -e.C0/e.C1 is already in the torus.
	// This absorbs the torus compression in the easy part.
	c := pr.Ext6.DivUnchecked(&e.C0, &e.C1)
	c = pr.Ext6.Neg(c)
	t0 := pr.FrobeniusSquareTorus(c)
	c = pr.MulTorus(t0, c)

	// 2. Hard part (up to permutation)
	// 3(p⁴-p²+1)/r
	// Daiki Hayashida, Kenichiro Hayasaka and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	// performed in torus compressed form
	t0 = pr.SquareTorus(c)
	t1 := pr.ExptHalfTorus(t0)
	t2 := pr.InverseTorus(c)
	t1 = pr.MulTorus(t1, t2)
	t2 = pr.ExptTorus(t1)
	t1 = pr.InverseTorus(t1)
	t1 = pr.MulTorus(t1, t2)
	t2 = pr.ExptTorus(t1)
	t1 = pr.FrobeniusTorus(t1)
	t1 = pr.MulTorus(t1, t2)
	c = pr.MulTorus(c, t0)
	t0 = pr.ExptTorus(t1)
	t2 = pr.ExptTorus(t0)
	t0 = pr.FrobeniusSquareTorus(t1)
	t1 = pr.InverseTorus(t1)
	t1 = pr.MulTorus(t1, t2)
	t1 = pr.MulTorus(t1, t0)

	var result GTEl
	// MulTorus(c, t1) requires c ≠ -t1. When c = -t1, it means the
	// product is 1 in the torus.
	if unsafe {
		// For a single pairing, this does not happen because the pairing is non-degenerate.
		result = *pr.DecompressTorus(pr.MulTorus(c, t1))
	} else {
		// For a product of pairings this might happen when the result is expected to be 1.
		// We assign a dummy value (1) to t1 and proceed furhter.
		// Finally we do a select on both edge cases:
		//   - Only if seletor1=0 and selector2=0, we return MulTorus(c, t1) decompressed.
		//   - Otherwise, we return 1.
		_sum := pr.Ext6.Add(c, t1)
		selector2 = pr.Ext6.IsZero(_sum)
		t1 = pr.Ext6.Select(selector2, _dummy, t1)
		selector := pr.api.Mul(pr.api.Sub(1, selector1), pr.api.Sub(1, selector2))
		result = *pr.Select(selector, pr.DecompressTorus(pr.MulTorus(c, t1)), pr.One())
	}

	return &result
}

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 - R0(x/y) - R1(1/y) = 0 instead of R0'*y - R1'*x - R2' = 0 This
// makes the multiplication by lines (MulBy014) and between lines (Mul014By014)
// circuit-efficient.
type lineEvaluation struct {
	R0, R1 fields_bls12381.E2
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.finalExponentiation(res, len(P) == 1)
	return res, nil
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
	pr.Ext12.AssertIsEqual(x, y)
}

func (pr Pairing) AssertIsOnCurve(P *G1Affine) {
	pr.curve.AssertIsOnCurve(P)
}

func (pr Pairing) AssertIsOnTwist(Q *G2Affine) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=4(1+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if Q=(0,0) we assign b=0 otherwise 3/(9+u), and continue
	selector := pr.api.And(pr.Ext2.IsZero(&Q.X), pr.Ext2.IsZero(&Q.Y))

	b := pr.Ext2.Select(selector, pr.Ext2.Zero(), pr.bTwist)

	left := pr.Ext2.Square(&Q.Y)
	right := pr.Ext2.Square(&Q.X)
	right = pr.Ext2.Mul(right, &Q.X)
	right = pr.Ext2.Add(right, b)
	pr.Ext2.AssertIsEqual(left, right)
}

func (pr Pairing) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	pr.AssertIsOnCurve(P)

	// 2- Check P has the right subgroup order
	// TODO: add phi and scalarMulBySeedSquare to g1.go
	// [x²]ϕ(P)
	phiP := pr.g1.phi(P)
	seedSquare := emulated.ValueOf[emulated.BLS12381Fr]("228988810152649578064853576960394133504")
	// TODO: use addchain to construct a fixed-scalar ScalarMul
	_P := pr.curve.ScalarMul(phiP, &seedSquare)
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

	res := pr.Ext12.One()

	var l1, l2 *lineEvaluation
	Qacc := make([]*G2Affine, n)
	yInv := make([]*emulated.Element[emulated.BLS12381Fp], n)
	xOverY := make([]*emulated.Element[emulated.BLS12381Fp], n)

	for k := 0; k < n; k++ {
		Qacc[k] = Q[k]
		// P and Q are supposed to be on G1 and G2 respectively of prime order r.
		// The point (x,0) is of order 2. But this function does not check
		// subgroup membership.
		// Anyway (x,0) cannot be on BLS12-381 because -4 is a cubic non-residue in Fp.
		// so, 1/y is well defined for all points P's
		yInv[k] = pr.curveF.Inverse(&P[k].Y)
		xOverY[k] = pr.curveF.MulMod(&P[k].X, yInv[k])
	}

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }

	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)

	// k = 0, separately to avoid MulBy034 (res × ℓ)

	// Qacc[k] ← 3Qacc[k],
	// l1 the tangent ℓ to 2Q[k]
	// l2 the line ℓ passing 2Q[k] and Q[k]
	Qacc[0], l1, l2 = pr.tripleStep(Qacc[0])
	// line evaluation at P[0]
	// and assign line to res (R1, R0, 0, 0, 1, 0)
	res.C0.B1 = *pr.MulByElement(&l1.R0, xOverY[0])
	res.C0.B0 = *pr.MulByElement(&l1.R1, yInv[0])
	res.C1.B1 = *pr.Ext2.One()
	// line evaluation at P[0]
	l2.R0 = *pr.MulByElement(&l2.R0, xOverY[0])
	l2.R1 = *pr.MulByElement(&l2.R1, yInv[0])
	// res = ℓ × ℓ
	prodLines := *pr.Mul014By014(&l2.R1, &l2.R0, &res.C0.B0, &res.C0.B1)
	res.C0.B0 = prodLines[0]
	res.C0.B1 = prodLines[1]
	res.C0.B2 = prodLines[2]
	res.C1.B1 = prodLines[3]
	res.C1.B2 = prodLines[4]

	for k := 1; k < n; k++ {
		// Qacc[k] ← 3Qacc[k],
		// l1 the tangent ℓ to 2Q[k]
		// l2 the line ℓ passing 2Q[k] and Q[k]
		Qacc[k], l1, l2 = pr.tripleStep(Qacc[k])
		// line evaluation at P[k]
		l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
		l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
		// line evaluation at P[k]
		l2.R0 = *pr.MulByElement(&l2.R0, xOverY[k])
		l2.R1 = *pr.MulByElement(&l2.R1, yInv[k])
		// ℓ × ℓ
		prodLines = *pr.Mul014By014(&l1.R1, &l1.R0, &l2.R1, &l2.R0)
		// (ℓ × ℓ) × res
		res = pr.MulBy01245(res, &prodLines)

	}

	// Compute ∏ᵢ { fᵢ_{u,Q}(P) }
	for i := 61; i >= 1; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res = pr.Square(res)

		if loopCounter[i] == 0 {
			for k := 0; k < n; k++ {
				// Qacc[k] ← 2Qacc[k] and l1 the tangent ℓ passing 2Qacc[k]
				Qacc[k], l1 = pr.doubleStep(Qacc[k])
				// line evaluation at P[k]
				l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
				l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
				// ℓ × res
				res = pr.MulBy014(res, &l1.R1, &l1.R0)
			}
		} else {
			for k := 0; k < n; k++ {
				// Qacc[k] ← 2Qacc[k]+Q[k],
				// l1 the line ℓ passing Qacc[k] and Q[k]
				// l2 the line ℓ passing (Qacc[k]+Q[k]) and Qacc[k]
				Qacc[k], l1, l2 = pr.doubleAndAddStep(Qacc[k], Q[k])
				// line evaluation at P[k]
				l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
				l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
				// line evaluation at P[k]
				l2.R0 = *pr.MulByElement(&l2.R0, xOverY[k])
				l2.R1 = *pr.MulByElement(&l2.R1, yInv[k])
				// ℓ × ℓ
				prodLines = *pr.Mul014By014(&l1.R1, &l1.R0, &l2.R1, &l2.R0)
				// (ℓ × ℓ) × res
				res = pr.MulBy01245(res, &prodLines)
			}
		}
	}

	// i = 0, separately to avoid a point doubling
	res = pr.Square(res)
	for k := 0; k < n; k++ {
		// l1 the tangent ℓ passing 2Qacc[k]
		l1 = pr.tangentCompute(Qacc[k])
		// line evaluation at P[k]
		l1.R0 = *pr.MulByElement(&l1.R0, xOverY[k])
		l1.R1 = *pr.MulByElement(&l1.R1, yInv[k])
		// ℓ × res
		res = pr.MulBy014(res, &l1.R1, &l1.R0)
	}

	// negative x₀
	res = pr.Ext12.Conjugate(res)

	return res, nil
}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) doubleAndAddStep(p1, p2 *G2Affine) (*G2Affine, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var p G2Affine

	// compute λ1 = (y2-y1)/(x2-x1)
	n := pr.Ext2.Sub(&p1.Y, &p2.Y)
	d := pr.Ext2.Sub(&p1.X, &p2.X)
	l1 := pr.Ext2.DivUnchecked(n, d)

	// compute x3 =λ1²-x1-x2
	x3 := pr.Ext2.Square(l1)
	x3 = pr.Ext2.Sub(x3, &p1.X)
	x3 = pr.Ext2.Sub(x3, &p2.X)

	// omit y3 computation

	// compute line1
	line1.R0 = *pr.Ext2.Neg(l1)
	line1.R1 = *pr.Ext2.Mul(l1, &p1.X)
	line1.R1 = *pr.Ext2.Sub(&line1.R1, &p1.Y)

	// compute λ2 = -λ1-2y1/(x3-x1)
	n = pr.Ext2.Double(&p1.Y)
	d = pr.Ext2.Sub(x3, &p1.X)
	l2 := pr.Ext2.DivUnchecked(n, d)
	l2 = pr.Ext2.Add(l2, l1)
	l2 = pr.Ext2.Neg(l2)

	// compute x4 = λ2²-x1-x3
	x4 := pr.Ext2.Square(l2)
	x4 = pr.Ext2.Sub(x4, &p1.X)
	x4 = pr.Ext2.Sub(x4, x3)

	// compute y4 = λ2(x1 - x4)-y1
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

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	λ := pr.Ext2.DivUnchecked(n, d)

	// xr = λ²-2x
	xr := pr.Ext2.Square(λ)
	xr = pr.Ext2.Sub(xr, &p1.X)
	xr = pr.Ext2.Sub(xr, &p1.X)

	// yr = λ(x-xr)-y
	yr := pr.Ext2.Sub(&p1.X, xr)
	yr = pr.Ext2.Mul(λ, yr)
	yr = pr.Ext2.Sub(yr, &p1.Y)

	p.X = *xr
	p.Y = *yr

	line.R0 = *pr.Ext2.Neg(λ)
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &p, &line

}

// addStep adds two points in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr Pairing) addStep(p1, p2 *G2Affine) (*G2Affine, *lineEvaluation) {

	// compute λ = (y2-y1)/(x2-x1)
	p2ypy := pr.Ext2.Sub(&p2.Y, &p1.Y)
	p2xpx := pr.Ext2.Sub(&p2.X, &p1.X)
	λ := pr.Ext2.DivUnchecked(p2ypy, p2xpx)

	// xr = λ²-x1-x2
	λλ := pr.Ext2.Square(λ)
	p2xpx = pr.Ext2.Add(&p1.X, &p2.X)
	xr := pr.Ext2.Sub(λλ, p2xpx)

	// yr = λ(x1-xr) - y1
	pxrx := pr.Ext2.Sub(&p1.X, xr)
	λpxrx := pr.Ext2.Mul(λ, pxrx)
	yr := pr.Ext2.Sub(λpxrx, &p1.Y)

	var res G2Affine
	res.X = *xr
	res.Y = *yr

	var line lineEvaluation
	line.R0 = *pr.Ext2.Neg(λ)
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &res, &line

}

// tripleStep triples p1 in affine coordinates, and evaluates the line in Miller loop
func (pr Pairing) tripleStep(p1 *G2Affine) (*G2Affine, *lineEvaluation, *lineEvaluation) {

	var line1, line2 lineEvaluation
	var res G2Affine

	// λ1 = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	λ1 := pr.Ext2.DivUnchecked(n, d)

	// compute line1
	line1.R0 = *pr.Ext2.Neg(λ1)
	line1.R1 = *pr.Ext2.Mul(λ1, &p1.X)
	line1.R1 = *pr.Ext2.Sub(&line1.R1, &p1.Y)

	// x2 = λ1²-2x
	x2 := pr.Ext2.Square(λ1)
	x2 = pr.Ext2.Sub(x2, &p1.X)
	x2 = pr.Ext2.Sub(x2, &p1.X)

	// ommit yr computation, and
	// compute λ2 = 2y/(x2 − x) − λ1.
	x1x2 := pr.Ext2.Sub(&p1.X, x2)
	λ2 := pr.Ext2.DivUnchecked(d, x1x2)
	λ2 = pr.Ext2.Sub(λ2, λ1)

	// compute line2
	line2.R0 = *pr.Ext2.Neg(λ2)
	line2.R1 = *pr.Ext2.Mul(λ2, &p1.X)
	line2.R1 = *pr.Ext2.Sub(&line2.R1, &p1.Y)

	// xr = λ²-p.x-x2
	λ2λ2 := pr.Ext2.Mul(λ2, λ2)
	qxrx := pr.Ext2.Add(x2, &p1.X)
	xr := pr.Ext2.Sub(λ2λ2, qxrx)

	// yr = λ(p.x-xr) - p.y
	pxrx := pr.Ext2.Sub(&p1.X, xr)
	λ2pxrx := pr.Ext2.Mul(λ2, pxrx)
	yr := pr.Ext2.Sub(λ2pxrx, &p1.Y)

	res.X = *xr
	res.Y = *yr

	return &res, &line1, &line2
}

// tangentCompute computes the line that goes through p1 and p2 but does not compute p1+p2
func (pr Pairing) tangentCompute(p1 *G2Affine) *lineEvaluation {

	// λ = 3x²/2y
	n := pr.Ext2.Square(&p1.X)
	three := big.NewInt(3)
	n = pr.Ext2.MulByConstElement(n, three)
	d := pr.Ext2.Double(&p1.Y)
	λ := pr.Ext2.DivUnchecked(n, d)

	var line lineEvaluation
	line.R0 = *pr.Ext2.Neg(λ)
	line.R1 = *pr.Ext2.Mul(λ, &p1.X)
	line.R1 = *pr.Ext2.Sub(&line.R1, &p1.Y)

	return &line

}

//		------------------------
//		  Fixed-argument pairing
//	    ------------------------
//
// The second argument Q is g2 the fixed canonical generator of G2.
//
// g2.X.A0 = 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
// g2.X.A1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
// g2.Y.A0 = 0xce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
// g2.Y.A1 = 0x606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be

// MillerLoopFixed computes the single Miller loop
// fᵢ_{u,g2}(P), where g2 is fixed.
func (pr Pairing) MillerLoopFixedQ(P *G1Affine) (*GTEl, error) {

	res := pr.Ext12.One()

	var yInv, xOverY *emulated.Element[emulated.BLS12381Fp]

	// P and Q are supposed to be on G1 and G2 respectively of prime order r.
	// The point (x,0) is of order 2. But this function does not check
	// subgroup membership.
	// Anyway (x,0) cannot be on BLS12-381 because -4 is a cubic non-residue in Fp.
	// so, 1/y is well defined for all points P's
	yInv = pr.curveF.Inverse(&P.Y)
	xOverY = pr.curveF.MulMod(&P.X, yInv)

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }

	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)
	res = pr.MulBy014(res,
		pr.MulByElement(&PrecomputedLines[1][62], yInv),
		pr.MulByElement(&PrecomputedLines[0][62], xOverY),
	)
	res = pr.MulBy014(res,
		pr.MulByElement(&PrecomputedLines[3][62], yInv),
		pr.MulByElement(&PrecomputedLines[2][62], xOverY),
	)

	// Compute ∏ᵢ { fᵢ_{u,Q}(P) }
	for i := 61; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res = pr.Square(res)

		if loopCounter[i] == 0 {
			res = pr.MulBy014(res,
				pr.MulByElement(&PrecomputedLines[1][i], yInv),
				pr.MulByElement(&PrecomputedLines[0][i], xOverY),
			)
		} else {
			res = pr.MulBy014(res,
				pr.MulByElement(&PrecomputedLines[1][i], yInv),
				pr.MulByElement(&PrecomputedLines[0][i], xOverY),
			)
			res = pr.MulBy014(res,
				pr.MulByElement(&PrecomputedLines[3][i], yInv),
				pr.MulByElement(&PrecomputedLines[2][i], xOverY),
			)
		}
	}

	// negative x₀
	res = pr.Ext12.Conjugate(res)

	return res, nil
}

// DoubleMillerLoopFixedQ computes the double Miller loop
// fᵢ_{u,g2}(T) * fᵢ_{u,Q}(P), where g2 is fixed.
func (pr Pairing) DoubleMillerLoopFixedQ(P, T *G1Affine, Q *G2Affine) (*GTEl, error) {
	res := pr.Ext12.One()

	var l1, l2 *lineEvaluation
	var Qacc *G2Affine
	Qacc = Q
	var yInv, xOverY, y2Inv, x2OverY2 *emulated.Element[emulated.BLS12381Fp]
	yInv = pr.curveF.Inverse(&P.Y)
	xOverY = pr.curveF.MulMod(&P.X, yInv)
	y2Inv = pr.curveF.Inverse(&T.Y)
	x2OverY2 = pr.curveF.MulMod(&T.X, y2Inv)

	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)

	// Qacc ← 3Qacc,
	// l1 the tangent ℓ to 2Q
	// l2 the line ℓ passing 2Q and Q
	Qacc, l1, l2 = pr.tripleStep(Qacc)
	// line evaluation at P
	// and assign line to res (R1, R0, 0, 0, 1, 0)
	res.C0.B1 = *pr.MulByElement(&l1.R0, xOverY)
	res.C0.B0 = *pr.MulByElement(&l1.R1, yInv)
	res.C1.B1 = *pr.Ext2.One()
	// line evaluation at P
	l2.R0 = *pr.MulByElement(&l2.R0, xOverY)
	l2.R1 = *pr.MulByElement(&l2.R1, yInv)
	// res = ℓ × ℓ
	prodLines := *pr.Mul014By014(&l2.R1, &l2.R0, &res.C0.B0, &res.C0.B1)
	res.C0.B0 = prodLines[0]
	res.C0.B1 = prodLines[1]
	res.C0.B2 = prodLines[2]
	res.C1.B1 = prodLines[3]
	res.C1.B2 = prodLines[4]

	res = pr.MulBy014(res,
		pr.MulByElement(&PrecomputedLines[1][62], y2Inv),
		pr.MulByElement(&PrecomputedLines[0][62], x2OverY2),
	)
	res = pr.MulBy014(res,
		pr.MulByElement(&PrecomputedLines[3][62], y2Inv),
		pr.MulByElement(&PrecomputedLines[2][62], x2OverY2),
	)

	// Compute ∏ᵢ { fᵢ_{u,G2}(T) }
	for i := 61; i >= 1; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res = pr.Square(res)

		if loopCounter[i] == 0 {
			res = pr.MulBy014(res,
				pr.MulByElement(&PrecomputedLines[1][i], y2Inv),
				pr.MulByElement(&PrecomputedLines[0][i], x2OverY2),
			)
			// Qacc ← 2Qacc and l1 the tangent ℓ passing 2Qacc
			Qacc, l1 = pr.doubleStep(Qacc)
			// line evaluation at P
			l1.R0 = *pr.MulByElement(&l1.R0, xOverY)
			l1.R1 = *pr.MulByElement(&l1.R1, yInv)
			// ℓ × res
			res = pr.MulBy014(res, &l1.R1, &l1.R0)
		} else {
			res = pr.MulBy014(res,
				pr.MulByElement(&PrecomputedLines[1][i], y2Inv),
				pr.MulByElement(&PrecomputedLines[0][i], x2OverY2),
			)
			res = pr.MulBy014(res,
				pr.MulByElement(&PrecomputedLines[3][i], y2Inv),
				pr.MulByElement(&PrecomputedLines[2][i], x2OverY2),
			)
			// Qacc ← 2Qacc+Q,
			// l1 the line ℓ passing Qacc and Q
			// l2 the line ℓ passing (Qacc+Q) and Qacc
			Qacc, l1, l2 = pr.doubleAndAddStep(Qacc, Q)
			// line evaluation at P
			l1.R0 = *pr.MulByElement(&l1.R0, xOverY)
			l1.R1 = *pr.MulByElement(&l1.R1, yInv)
			// line evaluation at P
			l2.R0 = *pr.MulByElement(&l2.R0, xOverY)
			l2.R1 = *pr.MulByElement(&l2.R1, yInv)
			// ℓ × ℓ
			prodLines = *pr.Mul014By014(&l1.R1, &l1.R0, &l2.R1, &l2.R0)
			// (ℓ × ℓ) × res
			res = pr.MulBy01245(res, &prodLines)

		}
	}

	// i = 0, separately to avoid a point doubling
	res = pr.Square(res)
	// l1 the tangent ℓ passing 2Qacc
	l1 = pr.tangentCompute(Qacc)
	// line evaluation at P
	l1.R0 = *pr.MulByElement(&l1.R0, xOverY)
	l1.R1 = *pr.MulByElement(&l1.R1, yInv)
	// ℓ × ℓ
	prodLines = *pr.Mul014By014(
		&l1.R1,
		&l1.R0,
		pr.MulByElement(&PrecomputedLines[1][0], y2Inv),
		pr.MulByElement(&PrecomputedLines[0][0], x2OverY2),
	)
	// (ℓ × ℓ) × res
	res = pr.MulBy01245(res, &prodLines)

	// negative x₀
	res = pr.Ext12.Conjugate(res)

	return res, nil
}

// PairFixedQ calculates the reduced pairing for a set of points
// e(P, g2), where g2 is fixed.
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr Pairing) PairFixedQ(P *G1Affine) (*GTEl, error) {
	res, err := pr.MillerLoopFixedQ(P)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.finalExponentiation(res, true)
	return res, nil
}

// DoublePairFixedQ calculates the reduced pairing for a set of points
// e(P, Q) * e(T, g2), where g2 is fixed.
//
// This function doesn't check that the inputs are in the correct subgroups.
func (pr Pairing) DoublePairFixedQ(P, T *G1Affine, Q *G2Affine) (*GTEl, error) {
	res, err := pr.DoubleMillerLoopFixedQ(P, T, Q)
	if err != nil {
		return nil, fmt.Errorf("double miller loop: %w", err)
	}
	res = pr.finalExponentiation(res, false)
	return res, nil
}
