package sw_bn254

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2 struct {
	api frontend.API
	fp  *emulated.Field[BaseField]
	fr  *emulated.Field[ScalarField]
	*fields_bn254.Ext2
	w    *emulated.Element[BaseField]
	u, v *fields_bn254.E2
	// GLV eigenvalue for endomorphism
	eigenvalue *emulated.Element[ScalarField]

	// Precomputed G2 generator and its multiple for GLV+FakeGLV
	g2Gen      *g2AffP // G2 generator
	g2GenNbits *g2AffP // [2^(nbits-1)]G2 where nbits = (r.BitLen()+3)/4 + 2
}

type g2AffP struct {
	X, Y fields_bn254.E2
}

// G2Affine represents G2 element with optional embedded line precomputations.
type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

func newG2AffP(v bn254.G2Affine) g2AffP {
	return g2AffP{
		X: fields_bn254.E2{
			A0: emulated.ValueOf[BaseField](v.X.A0),
			A1: emulated.ValueOf[BaseField](v.X.A1),
		},
		Y: fields_bn254.E2{
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
	// w = thirdRootOneG2 = thirdRootOneG1^2 (used for both psi2 and GLV endomorphism)
	w := fp.NewElement("21888242871839275220042445260109153167277707414472061641714758635765020556616")
	// GLV eigenvalue: lambda such that phi(P) = [lambda]P
	eigenvalue := fr.NewElement("4407920970296243842393367215006156084916469457145843978461")
	u := fields_bn254.E2{
		A0: *fp.NewElement("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
		A1: *fp.NewElement("10307601595873709700152284273816112264069230130616436755625194854815875713954"),
	}
	v := fields_bn254.E2{
		A0: *fp.NewElement("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
		A1: *fp.NewElement("3505843767911556378687030309984248845540243509899259641013678093033130930403"),
	}

	// Precomputed G2 generator for GLV+FakeGLV
	g2Gen := &g2AffP{
		X: fields_bn254.E2{
			A0: *fp.NewElement("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
			A1: *fp.NewElement("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
		},
		Y: fields_bn254.E2{
			A0: *fp.NewElement("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
			A1: *fp.NewElement("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
		},
	}
	// [2^(nbits-1)]G2 where nbits = (254+3)/4 + 2 = 66, so this is [2^65]G2
	// The loop does nbits-1 doublings, so the generator accumulates to [2^(nbits-1)]G2
	g2GenNbits := &g2AffP{
		X: fields_bn254.E2{
			A0: *fp.NewElement("6099622139700402640581725571890015148411145321742729577177999911575645303725"),
			A1: *fp.NewElement("9870328428465937988383794519490899227160817120884239055108452134207619193487"),
		},
		Y: fields_bn254.E2{
			A0: *fp.NewElement("16268382111792290652321980382595025991160708296314050973435867558225525677485"),
			A1: *fp.NewElement("15377126855853471483498618408547895055706247905282062963450025729940352455943"),
		},
	}

	return &G2{
		api:        api,
		fp:         fp,
		fr:         fr,
		Ext2:       fields_bn254.NewExt2(api),
		w:          w,
		eigenvalue: eigenvalue,
		u:          &u,
		v:          &v,
		// GLV+FakeGLV precomputed values
		g2Gen:      g2Gen,
		g2GenNbits: g2GenNbits,
	}, nil
}

func NewG2Affine(v bn254.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bn254.G2Affine) G2Affine {
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
	for i := 0; i < len(bn254.LoopCounter); i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}

func (g2 *G2) phi(q *G2Affine) *G2Affine {
	x := g2.Ext2.MulByElement(&q.P.X, g2.w)

	return &G2Affine{
		P: g2AffP{
			X: *x,
			Y: *g2.Ext2.Neg(&q.P.Y),
		},
	}
}

func (g2 *G2) psi(q *G2Affine) *G2Affine {
	x := g2.Ext2.Conjugate(&q.P.X)
	x = g2.Ext2.Mul(x, g2.u)
	y := g2.Ext2.Conjugate(&q.P.Y)
	y = g2.Ext2.Mul(y, g2.v)

	return &G2Affine{
		P: g2AffP{
			X: *x,
			Y: *y,
		},
	}
}

func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {
	z := g2.double(q)
	t0 := g2.add(q, z)
	t2 := g2.add(q, t0)
	t1 := g2.add(z, t2)
	z = g2.doubleAndAdd(t1, t0)
	t0 = g2.add(t0, z)
	t2 = g2.add(t2, t0)
	t1 = g2.add(t1, t2)
	t0 = g2.add(t0, t1)
	t1 = g2.add(t1, t0)
	t0 = g2.add(t0, t1)
	t2 = g2.add(t2, t0)
	t1 = g2.doubleAndAdd(t2, t1)
	t2 = g2.add(t2, t1)
	z = g2.add(z, t2)
	t2 = g2.add(t2, z)
	z = g2.doubleAndAdd(t2, z)
	t0 = g2.add(t0, z)
	t1 = g2.add(t1, t0)
	t3 := g2.double(t1)
	t3 = g2.doubleAndAdd(t3, t1)
	t2 = g2.add(t2, t3)
	t1 = g2.add(t1, t2)
	t2 = g2.add(t2, t1)
	t2 = g2.doubleN(t2, 16)
	t1 = g2.doubleAndAdd(t2, t1)
	t1 = g2.doubleN(t1, 13)
	t0 = g2.doubleAndAdd(t1, t0)
	t0 = g2.doubleN(t0, 15)
	z = g2.doubleAndAdd(t0, z)

	return z
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
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// p.y = λ(p.x-r.x) - p.y
	yr := g2.Ext2.Sub(&p.P.X, xr)
	yr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {mone, &λ.A1, &yr.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	yr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	yr = &fields_bn254.E2{A0: *yr0, A1: *yr1}

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
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(p-xr) - p.y
	yr := g2.Ext2.Sub(&p.P.X, xr)
	yr0 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A0}, {mone, &λ.A1, &yr.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	yr1 := g2.fp.Eval([][]*baseEl{{&λ.A0, &yr.A1}, {&λ.A1, &yr.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	yr = &fields_bn254.E2{A0: *yr0, A1: *yr1}

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

func (g2 G2) doubleAndAdd(p, q *G2Affine) *G2Affine {
	mone := g2.fp.NewElement(-1)

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.Ext2.Sub(&q.P.X, &p.P.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	x20 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {mone, &λ1.A1, &λ1.A1}, {mone, &p.P.X.A0}, {mone, &q.P.X.A0}}, []int{1, 1, 1, 1})
	x21 := g2.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {mone, &p.P.X.A1}, {mone, &q.P.X.A1}}, []int{2, 1, 1})
	x2 := &fields_bn254.E2{A0: *x20, A1: *x21}

	// omit y2 computation
	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := g2.Ext2.Add(&p.P.Y, &p.P.Y)
	x2xp := g2.Ext2.Sub(x2, &p.P.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &p.P.X.A0}, {mone, x20}}, []int{1, 1, 1, 1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &p.P.X.A1}, {mone, x21}}, []int{2, 1, 1})
	x3 := &fields_bn254.E2{A0: *x30, A1: *x31}

	// compute y3 = -λ2*(x3 - p.x)-p.y
	y3 := g2.Ext2.Sub(x3, &p.P.X)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {mone, &λ2.A1, &y3.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	y3 = &fields_bn254.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
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
	x2 := &fields_bn254.E2{A0: *x20, A1: *x21}

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.Sub(&p.P.X, x2)
	λ2 := g2.DivUnchecked(y2, x1x2)
	λ2 = g2.Sub(λ2, λ1)

	// compute x3 =λ2²-p.x-x2
	x30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {mone, &λ2.A1, &λ2.A1}, {mone, &p.P.X.A0}, {mone, x20}}, []int{1, 1, 1, 1})
	x31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {mone, &p.P.X.A1}, {mone, x21}}, []int{2, 1, 1})
	x3 := &fields_bn254.E2{A0: *x30, A1: *x31}

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.Ext2.Sub(&p.P.X, x3)
	y30 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A0}, {mone, &λ2.A1, &y3.A1}, {mone, &p.P.Y.A0}}, []int{1, 1, 1})
	y31 := g2.fp.Eval([][]*baseEl{{&λ2.A0, &y3.A1}, {&λ2.A1, &y3.A0}, {mone, &p.P.Y.A1}}, []int{1, 1, 1})
	y3 = &fields_bn254.E2{A0: *y30, A1: *y31}

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

// ScalarMul computes [s]Q using an efficient endomorphism and returns it. It doesn't modify Q nor s.
// It implements the GLV+fakeGLV optimization from [EEMP25] which achieves r^(1/4) bounds
// on the sub-scalars, reducing the number of iterations in the scalar multiplication loop.
//
// ⚠️  The scalar s must be nonzero and the point Q different from (0,0) unless [algopts.WithCompleteArithmetic] is set.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [EEMP25]: https://eprint.iacr.org/2025/933
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (g2 *G2) ScalarMul(Q *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	return g2.scalarMulGLVAndFakeGLV(Q, s, opts...)
}

// scalarMulGLVAndFakeGLV computes [s]Q using GLV+fakeGLV with r^(1/4) bounds.
// It implements the "GLV + fake GLV" explained in [EEMP25] (Sec. 3.3).
//
// ⚠️  The scalar s must be nonzero and the point Q different from (0,0) unless [algopts.WithCompleteArithmetic] is set.
//
// [EEMP25]: https://eprint.iacr.org/2025/933
func (g2 *G2) scalarMulGLVAndFakeGLV(Q *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}

	// handle 0-scalar
	var selector0 frontend.Variable
	_s := s
	if cfg.CompleteArithmetic {
		one := g2.fr.One()
		selector0 = g2.fr.IsZero(s)
		_s = g2.fr.Select(selector0, one, s)
	}

	// Instead of computing [s]Q=R, we check that R-[s]Q == 0.
	// This is equivalent to [v]R + [-s*v]Q = 0 for some nonzero v.
	//
	// Using LLL-based lattice reduction we find small sub-scalars:
	// 		[v1 + λ*v2]R + [u1 + λ*u2]Q = 0
	// 		[v1]R + [v2]Φ(R) + [u1]Q + [u2]Φ(Q) = 0
	//
	// where u1, u2, v1, v2 < c*r^{1/4} with c ≈ 1.25 (proven bound from LLL).

	// decompose s into u1, u2, v1, v2
	signs, sd, err := g2.fr.NewHintGeneric(rationalReconstructExtG2, 4, 4, nil, []*emulated.Element[ScalarField]{_s, g2.eigenvalue})
	if err != nil {
		panic(fmt.Sprintf("rationalReconstructExtG2 hint: %v", err))
	}
	u1, u2, v1, v2 := sd[0], sd[1], sd[2], sd[3]
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// Check that: s*(v1 + λ*v2) + u1 + λ*u2 = 0
	var st ScalarField
	sv1 := g2.fr.Mul(_s, v1)
	sλv2 := g2.fr.Mul(_s, g2.fr.Mul(g2.eigenvalue, v2))
	λu2 := g2.fr.Mul(g2.eigenvalue, u2)
	zero := g2.fr.Zero()

	lhs1 := g2.fr.Select(isNegv1, zero, sv1)
	lhs2 := g2.fr.Select(isNegv2, zero, sλv2)
	lhs3 := g2.fr.Select(isNegu1, zero, u1)
	lhs4 := g2.fr.Select(isNegu2, zero, λu2)
	lhs := g2.fr.Add(
		g2.fr.Add(lhs1, lhs2),
		g2.fr.Add(lhs3, lhs4),
	)

	rhs1 := g2.fr.Select(isNegv1, sv1, zero)
	rhs2 := g2.fr.Select(isNegv2, sλv2, zero)
	rhs3 := g2.fr.Select(isNegu1, u1, zero)
	rhs4 := g2.fr.Select(isNegu2, λu2, zero)
	rhs := g2.fr.Add(
		g2.fr.Add(rhs1, rhs2),
		g2.fr.Add(rhs3, rhs4),
	)

	g2.fr.AssertIsEqual(lhs, rhs)

	// Hint the scalar multiplication R = [s]Q
	_, point, _, err := emulated.NewVarGenericHint(g2.api, 0, 4, 0, nil,
		[]*emulated.Element[BaseField]{&Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1},
		[]*emulated.Element[ScalarField]{s},
		scalarMulG2Hint)
	if err != nil {
		panic(fmt.Sprintf("scalarMulG2Hint: %v", err))
	}
	R := &G2Affine{
		P: g2AffP{
			X: fields_bn254.E2{A0: *point[0], A1: *point[1]},
			Y: fields_bn254.E2{A0: *point[2], A1: *point[3]},
		},
	}
	// Preserve the original hinted R for return value (before edge-case modifications)
	originalR := R

	// handle (0,0)-point and edge cases
	var _selector0, _selector1 frontend.Variable
	_Q := Q
	if cfg.CompleteArithmetic {
		one := g2.Ext2.One()
		// if Q=(0,0) we assign a dummy point
		_selector0 = g2.api.And(g2.Ext2.IsZero(&Q.P.X), g2.Ext2.IsZero(&Q.P.Y))
		_Q = g2.Select(_selector0, &G2Affine{P: g2AffP{X: *one, Y: *one}}, Q)
		// if R.X == Q.X (happens when s=±1, so R=±Q), the incomplete addition fails
		// We check this BEFORE potentially modifying R
		_selector1 = g2.Ext2.IsZero(g2.Ext2.Sub(&Q.P.X, &R.P.X))
		// if s=0/s=-1 (selector0), Q=(0,0) (_selector0), or R.X==Q.X (_selector1),
		// we assign a dummy point to R
		selectorAny := g2.api.Or(g2.api.Or(selector0, _selector0), _selector1)
		R = g2.Select(selectorAny, &G2Affine{P: g2AffP{X: *one, Y: *one}}, R)
	}

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]*G2Affine
	negQY := g2.Ext2.Neg(&_Q.P.Y)
	tableQ[1] = &G2Affine{
		P: g2AffP{
			X: _Q.P.X,
			Y: *g2.Ext2.Select(isNegu1, negQY, &_Q.P.Y),
		},
	}
	tableQ[0] = g2.neg(tableQ[1])
	// For BN254 G2, glvPhi(Q) = (w * Q.X, Q.Y)
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&_Q.P.X, g2.w),
			Y: *g2.Ext2.Select(isNegu2, negQY, &_Q.P.Y),
		},
	}
	tablePhiQ[0] = g2.neg(tablePhiQ[1])

	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]*G2Affine
	negRY := g2.Ext2.Neg(&R.P.Y)
	tableR[1] = &G2Affine{
		P: g2AffP{
			X: R.P.X,
			Y: *g2.Ext2.Select(isNegv1, negRY, &R.P.Y),
		},
	}
	tableR[0] = g2.neg(tableR[1])
	tablePhiR[1] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&R.P.X, g2.w),
			Y: *g2.Ext2.Select(isNegv2, negRY, &R.P.Y),
		},
	}
	tablePhiR[0] = g2.neg(tablePhiR[1])

	// precompute -Q-R, Q+R, Q-R, -Q+R (combining the two points Q and R)
	// We use AddUnified for table precomputation to handle edge cases like s=1 where R=Q
	// and the points might be equal (requiring doubling instead of addition).
	var tableS [4]*G2Affine
	tableS[0] = g2.AddUnified(tableQ[0], tableR[0]) // -Q - R
	tableS[1] = g2.neg(tableS[0])                   // Q + R
	tableS[2] = g2.AddUnified(tableQ[1], tableR[0]) // Q - R
	tableS[3] = g2.neg(tableS[2])                   // -Q + R

	// precompute -Φ(Q)-Φ(R), Φ(Q)+Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R) (combining endomorphisms)
	var tablePhiS [4]*G2Affine
	tablePhiS[0] = g2.AddUnified(tablePhiQ[0], tablePhiR[0]) // -Φ(Q) - Φ(R)
	tablePhiS[1] = g2.neg(tablePhiS[0])                      // Φ(Q) + Φ(R)
	tablePhiS[2] = g2.AddUnified(tablePhiQ[1], tablePhiR[0]) // Φ(Q) - Φ(R)
	tablePhiS[3] = g2.neg(tablePhiS[2])                      // -Φ(Q) + Φ(R)

	// Acc = Q + Φ(Q) + R + Φ(R)
	Acc := g2.AddUnified(tableS[1], tablePhiS[1])
	B1 := Acc

	// Add G2 generator to Acc to avoid incomplete additions in the loop.
	// At the end, since [u1]Q + [u2]Φ(Q) + [v1]R + [v2]Φ(R) = 0,
	// Acc will equal [2^nbits]G2 (precomputed).
	g2GenPoint := &G2Affine{P: *g2.g2Gen}
	Acc = g2.add(Acc, g2GenPoint)

	// u1, u2, v1, v2 < c*r^{1/4} where c ≈ 1.25
	nbits := (st.Modulus().BitLen()+3)/4 + 2
	u1bits := g2.fr.ToBits(u1)
	u2bits := g2.fr.ToBits(u2)
	v1bits := g2.fr.ToBits(v1)
	v2bits := g2.fr.ToBits(v2)

	// Precompute all 16 combinations: ±Q ± Φ(Q) ± R ± Φ(R)
	// Using tableS (Q±R) and tablePhiS (Φ(Q)±Φ(R)) to match G1 pattern
	// B1 = (Q+R) + (Φ(Q)+Φ(R)) = Q + R + Φ(Q) + Φ(R)
	B2 := g2.AddUnified(tableS[1], tablePhiS[2]) // (Q+R) + (Φ(Q)-Φ(R)) = Q + R + Φ(Q) - Φ(R)
	B3 := g2.AddUnified(tableS[1], tablePhiS[3]) // (Q+R) + (-Φ(Q)+Φ(R)) = Q + R - Φ(Q) + Φ(R)
	B4 := g2.AddUnified(tableS[1], tablePhiS[0]) // (Q+R) + (-Φ(Q)-Φ(R)) = Q + R - Φ(Q) - Φ(R)
	B5 := g2.AddUnified(tableS[2], tablePhiS[1]) // (Q-R) + (Φ(Q)+Φ(R)) = Q - R + Φ(Q) + Φ(R)
	B6 := g2.AddUnified(tableS[2], tablePhiS[2]) // (Q-R) + (Φ(Q)-Φ(R)) = Q - R + Φ(Q) - Φ(R)
	B7 := g2.AddUnified(tableS[2], tablePhiS[3]) // (Q-R) + (-Φ(Q)+Φ(R)) = Q - R - Φ(Q) + Φ(R)
	B8 := g2.AddUnified(tableS[2], tablePhiS[0]) // (Q-R) + (-Φ(Q)-Φ(R)) = Q - R - Φ(Q) - Φ(R)
	B9 := g2.neg(B8)                             // -Q + R + Φ(Q) + Φ(R)
	B10 := g2.neg(B7)                            // -Q + R + Φ(Q) - Φ(R)
	B11 := g2.neg(B6)                            // -Q + R - Φ(Q) + Φ(R)
	B12 := g2.neg(B5)                            // -Q + R - Φ(Q) - Φ(R)
	B13 := g2.neg(B4)                            // -Q - R + Φ(Q) + Φ(R)
	B14 := g2.neg(B3)                            // -Q - R + Φ(Q) - Φ(R)
	B15 := g2.neg(B2)                            // -Q - R - Φ(Q) + Φ(R)
	B16 := g2.neg(B1)                            // -Q - R - Φ(Q) - Φ(R)

	var Bi *G2Affine
	for i := nbits - 1; i > 0; i-- {
		// selectorY takes values in [0,15]
		selectorY := g2.api.Add(
			u1bits[i],
			g2.api.Mul(u2bits[i], 2),
			g2.api.Mul(v1bits[i], 4),
			g2.api.Mul(v2bits[i], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := g2.api.Add(
			g2.api.Mul(selectorY, g2.api.Sub(1, g2.api.Mul(v2bits[i], 2))),
			g2.api.Mul(v2bits[i], 15),
		)

		// Bi.Y are distinct so we need a 16-to-1 multiplexer,
		// but only half of the Bi.X are distinct so we need an 8-to-1.
		Bi = &G2Affine{
			P: g2AffP{
				X: fields_bn254.E2{
					A0: *g2.fp.Mux(selectorX,
						&B16.P.X.A0, &B8.P.X.A0, &B14.P.X.A0, &B6.P.X.A0, &B12.P.X.A0, &B4.P.X.A0, &B10.P.X.A0, &B2.P.X.A0,
					),
					A1: *g2.fp.Mux(selectorX,
						&B16.P.X.A1, &B8.P.X.A1, &B14.P.X.A1, &B6.P.X.A1, &B12.P.X.A1, &B4.P.X.A1, &B10.P.X.A1, &B2.P.X.A1,
					),
				},
				Y: fields_bn254.E2{
					A0: *g2.fp.Mux(selectorY,
						&B16.P.Y.A0, &B8.P.Y.A0, &B14.P.Y.A0, &B6.P.Y.A0, &B12.P.Y.A0, &B4.P.Y.A0, &B10.P.Y.A0, &B2.P.Y.A0,
						&B15.P.Y.A0, &B7.P.Y.A0, &B13.P.Y.A0, &B5.P.Y.A0, &B11.P.Y.A0, &B3.P.Y.A0, &B9.P.Y.A0, &B1.P.Y.A0,
					),
					A1: *g2.fp.Mux(selectorY,
						&B16.P.Y.A1, &B8.P.Y.A1, &B14.P.Y.A1, &B6.P.Y.A1, &B12.P.Y.A1, &B4.P.Y.A1, &B10.P.Y.A1, &B2.P.Y.A1,
						&B15.P.Y.A1, &B7.P.Y.A1, &B13.P.Y.A1, &B5.P.Y.A1, &B11.P.Y.A1, &B3.P.Y.A1, &B9.P.Y.A1, &B1.P.Y.A1,
					),
				},
			},
		}
		// Acc = [2]Acc + Bi
		Acc = g2.doubleAndAdd(Acc, Bi)
	}

	// i = 0: subtract Q, Φ(Q), R, Φ(R) if the first bits are 0
	tableQ[0] = g2.add(tableQ[0], Acc)
	Acc = g2.Select(u1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = g2.add(tablePhiQ[0], Acc)
	Acc = g2.Select(u2bits[0], Acc, tablePhiQ[0])
	tableR[0] = g2.add(tableR[0], Acc)
	Acc = g2.Select(v1bits[0], Acc, tableR[0])
	tablePhiR[0] = g2.add(tablePhiR[0], Acc)
	Acc = g2.Select(v2bits[0], Acc, tablePhiR[0])

	// Acc should now be [2^(nbits-1)]G2 since [u1]Q + [u2]Φ(Q) + [v1]R + [v2]Φ(R) = 0
	// and we added G2 to the initial accumulator.
	expected := &G2Affine{P: *g2.g2GenNbits}

	if cfg.CompleteArithmetic {
		// if Q=(0,0), s=0, or R.X==Q.X, skip the check
		skip := g2.api.Or(g2.api.Or(selector0, _selector0), _selector1)
		Acc = g2.Select(skip, expected, Acc)
	}
	g2.AssertIsEqual(Acc, expected)

	if cfg.CompleteArithmetic {
		// if s=0 or Q=(0,0), return (0,0); otherwise return the original hinted R
		zeroE2 := g2.Ext2.Zero()
		returnZero := g2.api.Or(selector0, _selector0)
		return g2.Select(returnZero, &G2Affine{P: g2AffP{X: *zeroE2, Y: *zeroE2}}, originalR)
	}

	return R
}
