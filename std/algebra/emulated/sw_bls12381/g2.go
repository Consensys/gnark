package sw_bls12381

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2 struct {
	api frontend.API
	fp  *emulated.Field[BaseField]
	fr  *emulated.Field[ScalarField]
	*fields_bls12381.Ext2
	u1, w *emulated.Element[BaseField]
	v     *fields_bls12381.E2
}

type g2AffP struct {
	X, Y fields_bls12381.E2
}

// G2Affine represents G2 element with optional embedded line precomputations.
type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

func newG2AffP(v bls12381.G2Affine) g2AffP {
	return g2AffP{
		X: fields_bls12381.E2{
			A0: emulated.ValueOf[BaseField](v.X.A0),
			A1: emulated.ValueOf[BaseField](v.X.A1),
		},
		Y: fields_bls12381.E2{
			A0: emulated.ValueOf[BaseField](v.Y.A0),
			A1: emulated.ValueOf[BaseField](v.Y.A1),
		},
	}
}

func NewG2(api frontend.API) (*G2, error) {
	fp, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	fr, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	w := emulated.ValueOf[BaseField]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	u1 := emulated.ValueOf[BaseField]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	v := fields_bls12381.E2{
		A0: emulated.ValueOf[BaseField]("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
		A1: emulated.ValueOf[BaseField]("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"),
	}
	return &G2{
		api:  api,
		fp:   fp,
		fr:   fr,
		Ext2: fields_bls12381.NewExt2(api),
		w:    &w,
		u1:   &u1,
		v:    &v,
	}, nil
}

func NewG2Affine(v bls12381.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bls12381.G2Affine) G2Affine {
	if !v.IsInSubGroup() {
		// for the pairing check we check that G2 point is already in the
		// subgroup when we compute the lines in circuit. However, when the
		// point is given as a constant, then we already precompute the lines at
		// circuit compile time without explicitly checking the G2 membership.
		// So, we need to check that the point is in the subgroup before we
		// compute the lines.
		panic("given point is not in the G2 subgroup")
	}
	lines := precomputeLines(v)
	return G2Affine{
		P:     newG2AffP(v),
		Lines: &lines,
	}
}

// NewG2AffineFixedPlaceholder returns a placeholder for the circuit compilation
// when witness will be given with line precomputations using
// [NewG2AffineFixed].
func NewG2AffineFixedPlaceholder() G2Affine {
	var lines lineEvaluations
	for i := 0; i < len(bls12381.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}

func (g2 *G2) psi(q *G2Affine) *G2Affine {
	x := g2.Ext2.MulByElement(&q.P.X, g2.u1)
	y := g2.Ext2.Conjugate(&q.P.Y)
	y = g2.Ext2.Mul(y, g2.v)

	return &G2Affine{
		P: g2AffP{
			X: fields_bls12381.E2{A0: x.A1, A1: x.A0},
			Y: *y,
		},
	}
}

func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {

	z := g2.triple(q)
	z = g2.double(z)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 2)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 8)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 31)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 16)

	return g2.neg(z)
}

// AddUnified adds p and q and returns it. It doesn't modify p nor q.
//
// ✅ p can be equal to q, and either or both can be (0,0).
// ([0,0],[0,0]) is not on the twist but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It uses the unified formulas of Brier and Joye ([[BriJoy02]] (Corollary 1)).
//
// [BriJoy02]: https://link.springer.com/content/pdf/10.1007/3-540-45664-3_24.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (g2 *G2) AddUnified(p, q *G2Affine) *G2Affine {

	// selector1 = 1 when p is ([0,0],[0,0]) and 0 otherwise
	selector1 := g2.api.And(g2.Ext2.IsZero(&p.P.X), g2.Ext2.IsZero(&p.P.Y))
	// selector2 = 1 when q is ([0,0],[0,0]) and 0 otherwise
	selector2 := g2.api.And(g2.Ext2.IsZero(&q.P.X), g2.Ext2.IsZero(&q.P.Y))
	// λ = ((p.x+q.x)² - p.x*q.x + a)/(p.y + q.y)
	pxqx := g2.Mul(&p.P.X, &q.P.X)
	pxplusqx := g2.Add(&p.P.X, &q.P.X)
	num := g2.Mul(pxplusqx, pxplusqx)
	num = g2.Sub(num, pxqx)
	denum := g2.Add(&p.P.Y, &q.P.Y)
	// if p.y + q.y = 0, assign dummy 1 to denum and continue
	selector3 := g2.IsZero(denum)
	denum = g2.Ext2.Select(selector3, g2.One(), denum)
	λ := g2.DivUnchecked(num, denum)

	// x = λ^2 - p.x - q.x
	xr := g2.Mul(λ, λ)
	xr = g2.Sub(xr, pxplusqx)

	// y = λ(p.x - xr) - p.y
	yr := g2.Sub(&p.P.X, xr)
	yr = g2.Mul(yr, λ)
	yr = g2.Sub(yr, &p.P.Y)
	result := G2Affine{
		P:     g2AffP{X: *xr, Y: *yr},
		Lines: nil,
	}

	zero := g2.Ext2.Zero()
	infinity := G2Affine{
		P:     g2AffP{X: *zero, Y: *zero},
		Lines: nil,
	}
	// if p=([0,0],[0,0]) return q
	result = *g2.Select(selector1, q, &result)
	// if q=([0,0],[0,0]) return p
	result = *g2.Select(selector2, p, &result)
	// if p.y + q.y = 0, return ([0,0],[0,0])
	result = *g2.Select(selector3, &infinity, &result)

	return &result
}

func (g2 G2) add(p, q *G2Affine) *G2Affine {
	mone := g2.fp.NewElement(-1)

	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	qxpx := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ := g2.Ext2.DivUnchecked(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {mone, &λ.A1, &λ.A1}, {mone, &p.P.X.A0}, {mone, &q.P.X.A0}}, []int{1, 1, 1, 1})
	xr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {mone, &p.P.X.A1}, {mone, &q.P.X.A1}}, []int{2, 1, 1})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// p.y = λ(p.x-r.x) - p.y
	yr := g2.Ext2.Sub(&p.P.X, xr)
	yr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {mone, &λ.A1, &yr.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	yr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 G2) neg(p *G2Affine) *G2Affine {
	xr := &p.P.X
	yr := g2.Ext2.Neg(&p.P.Y)
	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 G2) sub(p, q *G2Affine) *G2Affine {
	qNeg := g2.neg(q)
	return g2.add(p, qNeg)
}

func (g2 *G2) double(p *G2Affine) *G2Affine {
	mone := g2.fp.NewElement(-1)

	// compute λ = (3p.x²)/2*p.y
	xx3a := g2.Square(&p.P.X)
	xx3a = g2.MulByConstElement(xx3a, big.NewInt(3))
	y2 := g2.Double(&p.P.Y)
	λ := g2.DivUnchecked(xx3a, y2)

	// xr = λ²-2p.x
	xr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {mone, &λ.A1, &λ.A1}, {mone, &p.P.X.A0}}, []int{1, 1, 2})
	xr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {mone, &p.P.X.A1}}, []int{2, 2})
	xr := &fields_bls12381.E2{A0: *xr0, A1: *xr1}

	// yr = λ(p-xr) - p.y
	yr := g2.Ext2.Sub(&p.P.X, xr)
	yr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {mone, &λ.A1, &yr.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	yr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	yr = &fields_bls12381.E2{A0: *yr0, A1: *yr1}

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 *G2) doubleN(p *G2Affine, n int) *G2Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g2.double(pn)
	}
	return pn
}

func (g2 G2) triple(p *G2Affine) *G2Affine {
	mone := g2.fp.NewElement(-1)

	// compute λ1 = (3p.x²)/2p.y
	xx := g2.Square(&p.P.X)
	xx = g2.MulByConstElement(xx, big.NewInt(3))
	y2 := g2.Double(&p.P.Y)
	λ1 := g2.DivUnchecked(xx, y2)

	// x2 = λ1²-2p.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {mone, &λ1.A1, &λ1.A1}, {mone, &p.P.X.A0}}, []int{1, 1, 2})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {mone, &p.P.X.A1}}, []int{2, 2})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.Sub(&p.P.X, x2)
	λ2 := g2.DivUnchecked(y2, x1x2)
	λ2 = g2.Sub(λ2, λ1)

	// compute x3 =λ2²-p.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &p.P.X.A0}, {mone, x20}}, []int{1, 1, 1, 1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &p.P.X.A1}, {mone, x21}}, []int{2, 1, 1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.Ext2.Sub(&p.P.X, x3)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {mone, &λ2.A1, &y3.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	y3 = &fields_bls12381.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

func (g2 G2) doubleAndAdd(p, q *G2Affine) *G2Affine {
	mone := g2.fp.NewElement(-1)

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {mone, &λ1.A1, &λ1.A1}, {mone, &p.P.X.A0}, {mone, &q.P.X.A0}}, []int{1, 1, 1, 1})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {mone, &p.P.X.A1}, {mone, &q.P.X.A1}}, []int{2, 1, 1})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit y2 computation
	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := g2.Ext2.Add(&p.P.Y, &p.P.Y)
	x2xp := g2.Ext2.Sub(x2, &p.P.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &p.P.X.A0}, {mone, x20}}, []int{1, 1, 1, 1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &p.P.X.A1}, {mone, x21}}, []int{2, 1, 1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// compute y3 = -λ2*(x3 - p.x)-p.y
	y3 := g2.Ext2.Sub(x3, &p.P.X)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {mone, &λ2.A1, &y3.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	y3 = &fields_bls12381.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

// doubleAndAddSelect is the same as doubleAndAdd but computes either:
//
//	2p+q if b=1 or
//	2q+p if b=0
//
// It first computes the x-coordinate of p+q via the slope(p,q)
// and then based on a Select adds either p or q.
func (g2 G2) doubleAndAddSelect(b frontend.Variable, p, q *G2Affine) *G2Affine {
	mone := g2.fp.NewElement(-1)

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {mone, &λ1.A1, &λ1.A1}, {mone, &p.P.X.A0}, {mone, &q.P.X.A0}}, []int{1, 1, 1, 1})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {mone, &p.P.X.A1}, {mone, &q.P.X.A1}}, []int{2, 1, 1})
	x2 := &fields_bls12381.E2{A0: *x20, A1: *x21}

	// omit y2 computation

	// conditional second addition
	t := g2.Select(b, p, q)

	// compute -λ2 = λ1+2*t.y/(x2-t.x)
	ypyp := g2.Ext2.Add(&t.P.Y, &t.P.Y)
	x2xp := g2.Ext2.Sub(x2, &t.P.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)

	// compute x3 = (-λ2)²-t.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &t.P.X.A0}, {mone, x20}}, []int{1, 1, 1, 1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &t.P.X.A1}, {mone, x21}}, []int{2, 1, 1})
	x3 := &fields_bls12381.E2{A0: *x30, A1: *x31}

	// compute y3 = -λ2*(x3 - t.x)-t.y
	y3 := g2.Ext2.Sub(x3, &t.P.X)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {mone, &λ2.A1, &y3.A1}, {mone, &t.P.Y.A0}}, []int{1, 1, 1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {mone, &t.P.Y.A1}}, []int{1, 1, 1})
	y3 = &fields_bls12381.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

func (g2 *G2) computeTwistEquation(Q *G2Affine) (left, right *fields_bls12381.E2) {
	// Twist: Y² == X³ + aX + b, where a=0 and b=4(1+u)
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)
	bTwist := fields_bls12381.E2{
		A0: emulated.ValueOf[BaseField]("4"),
		A1: emulated.ValueOf[BaseField]("4"),
	}
	// if Q=(0,0) we assign b=0 otherwise 4(1+u), and continue
	selector := g2.api.And(g2.Ext2.IsZero(&Q.P.X), g2.Ext2.IsZero(&Q.P.Y))
	b := g2.Ext2.Select(selector, g2.Ext2.Zero(), &bTwist)

	left = g2.Ext2.Square(&Q.P.Y)
	right = g2.Ext2.Square(&Q.P.X)
	right = g2.Ext2.Mul(right, &Q.P.X)
	right = g2.Ext2.Add(right, b)
	return left, right
}

func (g2 *G2) AssertIsOnTwist(Q *G2Affine) {
	left, right := g2.computeTwistEquation(Q)
	g2.Ext2.AssertIsEqual(left, right)
}

func (g2 *G2) AssertIsOnG2(Q *G2Affine) {
	// 1- Check Q is on the curve
	g2.AssertIsOnTwist(Q)

	// 2- Check Q has the right subgroup order
	// [x₀]Q
	xQ := g2.scalarMulBySeed(Q)
	// ψ(Q)
	psiQ := g2.psi(Q)

	// [r]Q == 0 <==>  ψ(Q) == [x₀]Q
	g2.AssertIsEqual(xQ, psiQ)
}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (g2 *G2) Select(b frontend.Variable, p, q *G2Affine) *G2Affine {
	x := g2.Ext2.Select(b, &p.P.X, &q.P.X)
	y := g2.Ext2.Select(b, &p.P.Y, &q.P.Y)
	return &G2Affine{
		P:     g2AffP{X: *x, Y: *y},
		Lines: nil,
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (g2 *G2) AssertIsEqual(p, q *G2Affine) {
	g2.Ext2.AssertIsEqual(&p.P.X, &q.P.X)
	g2.Ext2.AssertIsEqual(&p.P.Y, &q.P.Y)
}

func (g2 *G2) IsEqual(p, q *G2Affine) frontend.Variable {
	xEqual := g2.Ext2.IsEqual(&p.P.X, &q.P.X)
	yEqual := g2.Ext2.IsEqual(&p.P.Y, &q.P.Y)
	return g2.api.And(xEqual, yEqual)
}

// scalarMulGeneric computes [s]p and returns it. It doesn't modify p nor s.
// This function doesn't check that the p is on the curve. See AssertIsOnCurve.
//
// ⚠️  p must not be (0,0) and s must not be 0, unless [algopts.WithCompleteArithmetic] option is set.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It computes the right-to-left variable-base double-and-add algorithm ([Joye07], Alg.1).
//
// Since we use incomplete formulas for the addition law, we need to start with
// a non-zero accumulator point (R0). To do this, we skip the LSB (bit at
// position 0) and proceed assuming it was 1. At the end, we conditionally
// subtract the initial value (p) if LSB is 1. We also handle the bits at
// positions 1 and n-1 outside of the loop to optimize the number of
// constraints using [ELM03] (Section 3.1)
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
// [Joye07]: https://www.iacr.org/archive/ches2007/47270135/47270135.pdf
func (g2 *G2) scalarMulGeneric(p *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	var selector frontend.Variable
	if cfg.CompleteArithmetic {
		// if p=(0,0) we assign a dummy (0,1) to p and continue
		selector = g2.api.And(g2.Ext2.IsZero(&p.P.X), g2.Ext2.IsZero(&p.P.Y))
		one := g2.Ext2.One()
		p = g2.Select(selector, &G2Affine{P: g2AffP{X: *one, Y: *one}, Lines: nil}, p)
	}

	var st ScalarField
	sr := g2.fr.Reduce(s)
	sBits := g2.fr.ToBits(sr)
	n := st.Modulus().BitLen()
	if cfg.NbScalarBits > 2 && cfg.NbScalarBits < n {
		n = cfg.NbScalarBits
	}

	// i = 1
	Rb := g2.triple(p)
	R0 := g2.Select(sBits[1], Rb, p)
	R1 := g2.Select(sBits[1], p, Rb)

	for i := 2; i < n-1; i++ {
		Rb = g2.doubleAndAddSelect(sBits[i], R0, R1)
		R0 = g2.Select(sBits[i], Rb, R0)
		R1 = g2.Select(sBits[i], R1, Rb)
	}

	// i = n-1
	Rb = g2.doubleAndAddSelect(sBits[n-1], R0, R1)
	R0 = g2.Select(sBits[n-1], Rb, R0)

	// i = 0
	// we use AddUnified instead of Add. This is because:
	// 		- when s=0 then R0=P and AddUnified(P, -P) = (0,0). We return (0,0).
	// 		- when s=1 then R0=P AddUnified(Q, -Q) is well defined. We return R0=P.
	R0 = g2.Select(sBits[0], R0, g2.AddUnified(R0, g2.neg(p)))

	if cfg.CompleteArithmetic {
		// if p=(0,0), return (0,0)
		zero := g2.Ext2.Zero()
		R0 = g2.Select(selector, &G2Affine{P: g2AffP{X: *zero, Y: *zero}, Lines: nil}, R0)
	}

	return R0
}

// MultiScalarMul computes the multi scalar multiplication of the points P and
// scalars s. It returns an error if the length of the slices mismatch. If the
// input slices are empty, then returns point at infinity.
func (g2 *G2) MultiScalarMul(p []*G2Affine, s []*Scalar, opts ...algopts.AlgebraOption) (*G2Affine, error) {

	if len(p) == 0 {
		return &G2Affine{
			P: g2AffP{
				X: *g2.Ext2.Zero(),
				Y: *g2.Ext2.Zero(),
			},
			Lines: nil,
		}, nil
	}
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	addFn := g2.add
	if cfg.CompleteArithmetic {
		addFn = g2.AddUnified
	}
	if !cfg.FoldMulti {
		// the scalars are unique
		if len(p) != len(s) {
			return nil, fmt.Errorf("mismatching points and scalars slice lengths")
		}
		n := len(p)
		res := g2.scalarMulGeneric(p[0], s[0], opts...)
		for i := 1; i < n; i++ {
			q := g2.scalarMulGeneric(p[i], s[i], opts...)
			res = addFn(res, q)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(s) == 0 {
			return nil, fmt.Errorf("need scalar for folding")
		}
		gamma := s[0]
		res := g2.scalarMulGeneric(p[len(p)-1], gamma, opts...)
		for i := len(p) - 2; i > 0; i-- {
			res = addFn(p[i], res)
			res = g2.scalarMulGeneric(res, gamma, opts...)
		}
		res = addFn(p[0], res)
		return res, nil
	}
}
