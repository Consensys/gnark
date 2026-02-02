package sw_bls12381

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
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
	u1, w, w2  *emulated.Element[BaseField]
	eigenvalue *emulated.Element[ScalarField]
	v          *fields_bls12381.E2

	// SSWU map coefficients
	sswuCoeffA, sswuCoeffB *fields_bls12381.E2
	sswuZ                  *fields_bls12381.E2

	// Precomputed G2 generator and its multiple for GLV+FakeGLV
	g2Gen      *g2AffP // G2 generator
	g2GenNbits *g2AffP // [2^nbits]G2 where nbits = (r.BitLen()+3)/4 + 2
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
	w := fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	w2 := fp.NewElement("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350")
	eigenvalue := fr.NewElement("228988810152649578064853576960394133503")
	u1 := fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	v := fields_bls12381.E2{
		A0: *fp.NewElement("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
		A1: *fp.NewElement("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"),
	}
	sswuCoeffA, sswuCoeffB := hash_to_curve.G2SSWUIsogenyCurveCoefficients()
	coeffA := &fields_bls12381.E2{
		A0: *fp.NewElement(sswuCoeffA.A0),
		A1: *fp.NewElement(sswuCoeffA.A1),
	}
	coeffB := &fields_bls12381.E2{
		A0: *fp.NewElement(sswuCoeffB.A0),
		A1: *fp.NewElement(sswuCoeffB.A1),
	}
	sswuZ := hash_to_curve.G2SSWUIsogenyZ()
	z := &fields_bls12381.E2{
		A0: *fp.NewElement(sswuZ.A0),
		A1: *fp.NewElement(sswuZ.A1),
	}

	// Precomputed G2 generator for GLV+FakeGLV
	g2Gen := &g2AffP{
		X: fields_bls12381.E2{
			A0: *fp.NewElement("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160"),
			A1: *fp.NewElement("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758"),
		},
		Y: fields_bls12381.E2{
			A0: *fp.NewElement("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905"),
			A1: *fp.NewElement("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"),
		},
	}
	// [2^(nbits-1)]G2 where nbits = (255+3)/4 + 2 = 66, so this is [2^65]G2
	// The loop does nbits-1 doublings, so the generator accumulates to [2^(nbits-1)]G2
	g2GenNbits := &g2AffP{
		X: fields_bls12381.E2{
			A0: *fp.NewElement("1307001654908388153254394944417118155033503188409787277795273489312551176370209873126740711463572657296916966732684"),
			A1: *fp.NewElement("1066804690119577865989830850277879393407029322116864061755683314318400220056817483617033672656485029228353937929571"),
		},
		Y: fields_bls12381.E2{
			A0: *fp.NewElement("1233864651366532660795929818904272589705597977637697925481983092108793193162343169655985724823869788077854535468808"),
			A1: *fp.NewElement("2703972434797875065063829955607449483769333186572810763171217085444622779819503421195150761462859837038921185079043"),
		},
	}

	return &G2{
		api:        api,
		fp:         fp,
		fr:         fr,
		Ext2:       fields_bls12381.NewExt2(api),
		w:          w,
		w2:         w2,
		eigenvalue: eigenvalue,
		u1:         u1,
		v:          &v,
		// SSWU map
		sswuCoeffA: coeffA,
		sswuCoeffB: coeffB,
		sswuZ:      z,
		// GLV+FakeGLV precomputed values
		g2Gen:      g2Gen,
		g2GenNbits: g2GenNbits,
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

func (g2 *G2) psi2(q *G2Affine) *G2Affine {
	x := g2.Ext2.MulByElement(&q.P.X, g2.w)
	y := g2.Ext2.Neg(&q.P.Y)

	return &G2Affine{
		P: g2AffP{
			X: *x,
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
	result := &G2Affine{
		P:     g2AffP{X: *xr, Y: *yr},
		Lines: nil,
	}

	zero := g2.Ext2.Zero()
	infinity := G2Affine{
		P:     g2AffP{X: *zero, Y: *zero},
		Lines: nil,
	}
	// if p=([0,0],[0,0]) return q
	result = g2.Select(selector1, q, result)
	// if q=([0,0],[0,0]) return p
	result = g2.Select(selector2, p, result)
	// if p.y + q.y = 0, return ([0,0],[0,0])
	result = g2.Select(selector3, &infinity, result)

	return result
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
		A0: *g2.fp.NewElement("4"),
		A1: *g2.fp.NewElement("4"),
	}
	// if Q=(0,0) we assign b=0 otherwise 4(1+u), and continue
	selector := g2.api.And(g2.Ext2.IsZero(&Q.P.X), g2.Ext2.IsZero(&Q.P.Y))
	b := g2.Ext2.Select(selector, g2.Ext2.Zero(), &bTwist)

	left = g2.Ext2.Square(&Q.P.Y)
	mone := g2.fp.NewElement(-1)
	right = &fields_bls12381.E2{
		A0: *g2.fp.Eval([][]*baseEl{{&Q.P.X.A0, &Q.P.X.A0, &Q.P.X.A0}, {mone, &Q.P.X.A0, &Q.P.X.A1, &Q.P.X.A1}, {&b.A0}}, []int{1, 3, 1}),
		A1: *g2.fp.Eval([][]*baseEl{{&Q.P.X.A1, &Q.P.X.A0, &Q.P.X.A0}, {mone, &Q.P.X.A1, &Q.P.X.A1, &Q.P.X.A1}, {&b.A1}}, []int{3, 1, 1}),
	}

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
	sBits := g2.fr.ToBitsCanonical(s)
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

// ScalarMul computes [s]Q using an efficient endomorphism and returns it. It doesn't modify Q nor s.
// It implements the GLV+fakeGLV optimization from [EEMP25] which achieves r^(1/4) bounds
// on the sub-scalars, reducing the number of iterations in the scalar multiplication loop.
//
// Benchmarks show ~36% fewer constraints compared to plain GLV:
//   - GLV: ~914k constraints
//   - GLV+FakeGLV: ~585k constraints
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

// scalarMulGLV computes [s]Q using an efficient endomorphism and returns it. It doesn't modify Q nor s.
// It implements an optimized version based on algorithm 1 of [Halo] (see Section 6.2 and appendix C).
//
// ⚠️  The scalar s must be nonzero and the point Q different from (0,0) unless [algopts.WithCompleteArithmetic] is set.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [Halo]: https://eprint.iacr.org/2019/1021.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (g2 *G2) scalarMulGLV(Q *G2Affine, s *Scalar, opts ...algopts.AlgebraOption) *G2Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	addFn := g2.add
	var selector frontend.Variable
	if cfg.CompleteArithmetic {
		addFn = g2.AddUnified
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		selector = g2.api.And(
			g2.api.And(g2.fp.IsZero(&Q.P.X.A0), g2.fp.IsZero(&Q.P.X.A1)),
			g2.api.And(g2.fp.IsZero(&Q.P.Y.A0), g2.fp.IsZero(&Q.P.Y.A1)),
		)
		one := g2.Ext2.One()
		Q = g2.Select(selector, &G2Affine{P: g2AffP{X: *one, Y: *one}, Lines: nil}, Q)
	}

	// We use the endomorphism à la GLV to compute [s]Q as
	// 		[s1]Q + [s2]Φ(Q)
	// the sub-scalars s1, s2 can be negative (bigints) in the hint. If so,
	// they will be reduced in-circuit modulo the SNARK scalar field and not
	// the emulated field. So we return in the hint |s1|, |s2| and boolean
	// flags sdBits to negate the points Q, Φ(Q) instead of the corresponding
	// sub-scalars.

	// decompose s into s1 and s2
	sdBits, sd, err := g2.fr.NewHintGeneric(decomposeScalarG1, 2, 2, nil, []*emulated.Element[ScalarField]{s, g2.eigenvalue})
	if err != nil {
		panic(fmt.Sprintf("compute GLV decomposition: %v", err))
	}
	s1, s2 := sd[0], sd[1]
	selector1, selector2 := sdBits[0], sdBits[1]
	s3 := g2.fr.Select(selector1, g2.fr.Neg(s1), s1)
	s4 := g2.fr.Select(selector2, g2.fr.Neg(s2), s2)
	// s == s3 + [λ]s4
	g2.fr.AssertIsEqual(
		g2.fr.Add(s3, g2.fr.Mul(s4, g2.eigenvalue)),
		s,
	)

	s1bits := g2.fr.ToBits(s1)
	s2bits := g2.fr.ToBits(s2)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [3]*G2Affine
	negQY := g2.Ext2.Neg(&Q.P.Y)
	tableQ[1] = &G2Affine{
		P: g2AffP{
			X: Q.P.X,
			Y: *g2.Ext2.Select(selector1, negQY, &Q.P.Y),
		},
	}
	tableQ[0] = g2.neg(tableQ[1])
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&Q.P.X, g2.w2),
			Y: *g2.Ext2.Select(selector2, negQY, &Q.P.Y),
		},
	}
	tablePhiQ[0] = g2.neg(tablePhiQ[1])
	tableQ[2] = g2.triple(tableQ[1])
	tablePhiQ[2] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&tableQ[2].P.X, g2.w2),
			Y: *g2.Ext2.Select(selector2, g2.Ext2.Neg(&tableQ[2].P.Y), &tableQ[2].P.Y),
		},
	}

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q)
	Acc := g2.add(tableQ[1], tablePhiQ[1])

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point P from:
	// 		B1 = Q+Φ(Q)
	// 		B2 = -Q-Φ(Q)
	// 		B3 = Q-Φ(Q)
	// 		B4 = -Q+Φ(Q)
	//
	// If we extend this by merging two iterations, we need to look up P and P'
	// both from {B1, B2, B3, B4} and compute:
	// 		[2]([2]Acc+P)+P' = [4]Acc + T
	// where T = [2]P+P'. So at each (merged) iteration, we can compute [4]Acc
	// and look up T from the precomputed list of points:
	//
	// T = [3](Q + Φ(Q))
	// P = B1 and P' = B1
	T1 := g2.add(tableQ[2], tablePhiQ[2])
	// T = Q + Φ(Q)
	// P = B1 and P' = B2
	T2 := Acc
	// T = [3]Q + Φ(Q)
	// P = B1 and P' = B3
	T3 := g2.add(tableQ[2], tablePhiQ[1])
	// T = Q + [3]Φ(Q)
	// P = B1 and P' = B4
	T4 := g2.add(tableQ[1], tablePhiQ[2])
	// T  = -Q - Φ(Q)
	// P = B2 and P' = B1
	T5 := g2.neg(T2)
	// T  = -[3](Q + Φ(Q))
	// P = B2 and P' = B2
	T6 := g2.neg(T1)
	// T = -Q - [3]Φ(Q)
	// P = B2 and P' = B3
	T7 := g2.neg(T4)
	// T = -[3]Q - Φ(Q)
	// P = B2 and P' = B4
	T8 := g2.neg(T3)
	// T = [3]Q - Φ(Q)
	// P = B3 and P' = B1
	T9 := g2.add(tableQ[2], tablePhiQ[0])
	// T = Q - [3]Φ(Q)
	// P = B3 and P' = B2
	T11 := g2.neg(tablePhiQ[2])
	T10 := g2.add(tableQ[1], T11)
	// T = [3](Q - Φ(Q))
	// P = B3 and P' = B3
	T11 = g2.add(tableQ[2], T11)
	// T = -Φ(Q) + Q
	// P = B3 and P' = B4
	T12 := g2.add(tablePhiQ[0], tableQ[1])
	// T = [3]Φ(Q) - Q
	// P = B4 and P' = B1
	T13 := g2.neg(T10)
	// T = Φ(Q) - [3]Q
	// P = B4 and P' = B2
	T14 := g2.neg(T9)
	// T = Φ(Q) - Q
	// P = B4 and P' = B3
	T15 := g2.neg(T12)
	// T = [3](Φ(Q) - Q)
	// P = B4 and P' = B4
	T16 := g2.neg(T11)
	// note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	nbits := 130
	for i := nbits - 2; i > 0; i -= 2 {
		// selectorY takes values in [0,15]
		selectorY := g2.api.Add(
			s1bits[i],
			g2.api.Mul(s2bits[i], 2),
			g2.api.Mul(s1bits[i-1], 4),
			g2.api.Mul(s2bits[i-1], 8),
		)
		// selectorX takes values in [0,7] s.t.:
		// 		- when selectorY < 8: selectorX = selectorY
		// 		- when selectorY >= 8: selectorX = 15 - selectorY
		selectorX := g2.api.Add(
			g2.api.Mul(selectorY, g2.api.Sub(1, g2.api.Mul(s2bits[i-1], 2))),
			g2.api.Mul(s2bits[i-1], 15),
		)
		// Bi.Y are distincts so we need a 16-to-1 multiplexer,
		// but only half of the Bi.X are distinct so we need a 8-to-1.
		T := &G2Affine{
			P: g2AffP{
				X: fields_bls12381.E2{
					A0: *g2.fp.Mux(selectorX, &T6.P.X.A0, &T10.P.X.A0, &T14.P.X.A0, &T2.P.X.A0, &T7.P.X.A0, &T11.P.X.A0, &T15.P.X.A0, &T3.P.X.A0),
					A1: *g2.fp.Mux(selectorX, &T6.P.X.A1, &T10.P.X.A1, &T14.P.X.A1, &T2.P.X.A1, &T7.P.X.A1, &T11.P.X.A1, &T15.P.X.A1, &T3.P.X.A1),
				},
				Y: fields_bls12381.E2{
					A0: *g2.fp.Mux(selectorY,
						&T6.P.Y.A0, &T10.P.Y.A0, &T14.P.Y.A0, &T2.P.Y.A0, &T7.P.Y.A0, &T11.P.Y.A0, &T15.P.Y.A0, &T3.P.Y.A0,
						&T8.P.Y.A0, &T12.P.Y.A0, &T16.P.Y.A0, &T4.P.Y.A0, &T5.P.Y.A0, &T9.P.Y.A0, &T13.P.Y.A0, &T1.P.Y.A0,
					),
					A1: *g2.fp.Mux(selectorY,
						&T6.P.Y.A1, &T10.P.Y.A1, &T14.P.Y.A1, &T2.P.Y.A1, &T7.P.Y.A1, &T11.P.Y.A1, &T15.P.Y.A1, &T3.P.Y.A1,
						&T8.P.Y.A1, &T12.P.Y.A1, &T16.P.Y.A1, &T4.P.Y.A1, &T5.P.Y.A1, &T9.P.Y.A1, &T13.P.Y.A1, &T1.P.Y.A1,
					),
				},
			},
		}
		// Acc = [4]Acc + T
		Acc = g2.double(Acc)
		Acc = g2.doubleAndAdd(Acc, T)
	}

	// i = 0
	// subtract the Q, Φ(Q) if the first bits are 0.
	// When cfg.CompleteArithmetic is set, we use AddUnified instead of Add.
	// This means when s=0 then Acc=(0,0) because AddUnified(Q, -Q) = (0,0).
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = g2.Select(s1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = addFn(tablePhiQ[0], Acc)
	Acc = g2.Select(s2bits[0], Acc, tablePhiQ[0])

	if cfg.CompleteArithmetic {
		zero := g2.Ext2.Zero()
		Acc = g2.Select(selector, &G2Affine{P: g2AffP{X: *zero, Y: *zero}}, Acc)
	}

	return Acc
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
	// Using Eisenstein decomposition:
	// 		[v1 + λ*v2]R + [u1 + λ*u2]Q = 0
	// 		[v1]R + [v2]Φ(R) + [u1]Q + [u2]Φ(Q) = 0
	//
	// where u1, u2, v1, v2 < r^{1/4} (up to a constant factor).

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
			X: fields_bls12381.E2{A0: *point[0], A1: *point[1]},
			Y: fields_bls12381.E2{A0: *point[2], A1: *point[3]},
		},
	}

	// handle (0,0)-point
	var _selector0 frontend.Variable
	_Q := Q
	if cfg.CompleteArithmetic {
		// if R=(0,0) we assign a dummy point
		one := g2.Ext2.One()
		R = g2.Select(selector0, &G2Affine{P: g2AffP{X: *one, Y: *one}}, R)
		// if Q=(0,0) we assign a dummy point
		_selector0 = g2.api.And(g2.Ext2.IsZero(&Q.P.X), g2.Ext2.IsZero(&Q.P.Y))
		_Q = g2.Select(_selector0, &G2Affine{P: g2AffP{X: *one, Y: *one}}, Q)
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
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: *g2.Ext2.MulByElement(&_Q.P.X, g2.w2),
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
			X: *g2.Ext2.MulByElement(&R.P.X, g2.w2),
			Y: *g2.Ext2.Select(isNegv2, negRY, &R.P.Y),
		},
	}
	tablePhiR[0] = g2.neg(tablePhiR[1])

	// precompute -Q-R, Q+R, Q-R, -Q+R (combining the two points Q and R)
	var tableS [4]*G2Affine
	tableS[0] = g2.add(tableQ[0], tableR[0]) // -Q - R
	tableS[1] = g2.neg(tableS[0])            // Q + R
	tableS[2] = g2.add(tableQ[1], tableR[0]) // Q - R
	tableS[3] = g2.neg(tableS[2])            // -Q + R

	// precompute -Φ(Q)-Φ(R), Φ(Q)+Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R) (combining endomorphisms)
	var tablePhiS [4]*G2Affine
	tablePhiS[0] = g2.add(tablePhiQ[0], tablePhiR[0]) // -Φ(Q) - Φ(R)
	tablePhiS[1] = g2.neg(tablePhiS[0])               // Φ(Q) + Φ(R)
	tablePhiS[2] = g2.add(tablePhiQ[1], tablePhiR[0]) // Φ(Q) - Φ(R)
	tablePhiS[3] = g2.neg(tablePhiS[2])               // -Φ(Q) + Φ(R)

	// Acc = Q + Φ(Q) + R + Φ(R)
	Acc := g2.add(tableS[1], tablePhiS[1])
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
	B2 := g2.add(tableS[1], tablePhiS[2]) // (Q+R) + (Φ(Q)-Φ(R)) = Q + R + Φ(Q) - Φ(R)
	B3 := g2.add(tableS[1], tablePhiS[3]) // (Q+R) + (-Φ(Q)+Φ(R)) = Q + R - Φ(Q) + Φ(R)
	B4 := g2.add(tableS[1], tablePhiS[0]) // (Q+R) + (-Φ(Q)-Φ(R)) = Q + R - Φ(Q) - Φ(R)
	B5 := g2.add(tableS[2], tablePhiS[1]) // (Q-R) + (Φ(Q)+Φ(R)) = Q - R + Φ(Q) + Φ(R)
	B6 := g2.add(tableS[2], tablePhiS[2]) // (Q-R) + (Φ(Q)-Φ(R)) = Q - R + Φ(Q) - Φ(R)
	B7 := g2.add(tableS[2], tablePhiS[3]) // (Q-R) + (-Φ(Q)+Φ(R)) = Q - R - Φ(Q) + Φ(R)
	B8 := g2.add(tableS[2], tablePhiS[0]) // (Q-R) + (-Φ(Q)-Φ(R)) = Q - R - Φ(Q) - Φ(R)
	B9 := g2.neg(B8)                      // -Q + R + Φ(Q) + Φ(R)
	B10 := g2.neg(B7)                     // -Q + R + Φ(Q) - Φ(R)
	B11 := g2.neg(B6)                     // -Q + R - Φ(Q) + Φ(R)
	B12 := g2.neg(B5)                     // -Q + R - Φ(Q) - Φ(R)
	B13 := g2.neg(B4)                     // -Q - R + Φ(Q) + Φ(R)
	B14 := g2.neg(B3)                     // -Q - R + Φ(Q) - Φ(R)
	B15 := g2.neg(B2)                     // -Q - R - Φ(Q) + Φ(R)
	B16 := g2.neg(B1)                     // -Q - R - Φ(Q) - Φ(R)

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
				X: fields_bls12381.E2{
					A0: *g2.fp.Mux(selectorX,
						&B16.P.X.A0, &B8.P.X.A0, &B14.P.X.A0, &B6.P.X.A0, &B12.P.X.A0, &B4.P.X.A0, &B10.P.X.A0, &B2.P.X.A0,
					),
					A1: *g2.fp.Mux(selectorX,
						&B16.P.X.A1, &B8.P.X.A1, &B14.P.X.A1, &B6.P.X.A1, &B12.P.X.A1, &B4.P.X.A1, &B10.P.X.A1, &B2.P.X.A1,
					),
				},
				Y: fields_bls12381.E2{
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

	// Acc should now be [2^nbits]G2 since [u1]Q + [u2]Φ(Q) + [v1]R + [v2]Φ(R) = 0
	// and we added G2 to the initial accumulator.
	expected := &G2Affine{P: *g2.g2GenNbits}

	if cfg.CompleteArithmetic {
		// if Q=(0,0) or s=0, skip the check
		skip := g2.api.Or(selector0, _selector0)
		Acc = g2.Select(skip, expected, Acc)
	}
	g2.AssertIsEqual(Acc, expected)

	if cfg.CompleteArithmetic {
		zeroE2 := g2.Ext2.Zero()
		R = g2.Select(selector0, &G2Affine{P: g2AffP{X: *zeroE2, Y: *zeroE2}}, R)
	}

	return R
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
		res := g2.scalarMulGLV(p[0], s[0], opts...)
		for i := 1; i < n; i++ {
			q := g2.scalarMulGLV(p[i], s[i], opts...)
			res = addFn(res, q)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(s) == 0 {
			return nil, fmt.Errorf("need scalar for folding")
		}
		gamma := s[0]
		res := g2.scalarMulGLV(p[len(p)-1], gamma, opts...)
		for i := len(p) - 2; i > 0; i-- {
			res = addFn(p[i], res)
			res = g2.scalarMulGLV(res, gamma, opts...)
		}
		res = addFn(p[0], res)
		return res, nil
	}
}
