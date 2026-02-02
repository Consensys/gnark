package sw_bw6761

import (
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// g2AffP is the raw G2 element without precomputations.
type g2AffP = sw_emulated.AffinePoint[BaseField]

// G2Affine represents G2 element with optional embedded line precomputations.
type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

func newG2AffP(v bw6761.G2Affine) g2AffP {
	return sw_emulated.AffinePoint[BaseField]{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

// NewG2Affine returns the witness of v without precomputations. In case of
// pairing the precomputation will be done in-circuit.
func NewG2Affine(v bw6761.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bw6761.G2Affine) G2Affine {
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
	for i := 0; i < len(bw6761.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}

type G2 struct {
	api    frontend.API
	curveF *emulated.Field[BaseField]
	fr     *emulated.Field[ScalarField]
	w      *emulated.Element[BaseField]
	// GLV eigenvalue for endomorphism
	eigenvalue *emulated.Element[ScalarField]

	// Precomputed G2 generator and its multiple for GLV+FakeGLV
	g2Gen      *g2AffP // G2 generator
	g2GenNbits *g2AffP // [2^(nbits-1)]G2 where nbits = (r.BitLen()+3)/4 + 2
}

func NewG2(api frontend.API) (*G2, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	fr, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	// w = thirdRootOneG2 = thirdRootOneG1^2 (used for GLV endomorphism)
	w := ba.NewElement("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648")
	// GLV eigenvalue: lambda such that phi(P) = [lambda]P
	eigenvalue := fr.NewElement("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945")

	// Precomputed G2 generator for GLV+FakeGLV
	g2Gen := &g2AffP{
		X: *ba.NewElement("6445332910596979336035888152774071626898886139774101364933948236926875073754470830732273879639675437155036544153105017729592600560631678554299562762294743927912429096636156401171909259073181112518725201388196280039960074422214428"),
		Y: *ba.NewElement("562923658089539719386922163444547387757586534741080263946953401595155211934630598999300396317104182598044793758153214972605680357108252243146746187917218885078195819486220416605630144001533548163105316661692978285266378674355041"),
	}
	// [2^(nbits-1)]G2 where nbits = (377+3)/4 + 2 = 97, so this is [2^96]G2
	// The loop does nbits-1 doublings, so the generator accumulates to [2^(nbits-1)]G2
	g2GenNbits := &g2AffP{
		X: *ba.NewElement("3095984673093732516312387265169694060996602327701627003095800025572039633257324043941471095859774515229409057356532230556857309141882262691503434703676863345821048055421798431014967860961114720963410640620563703233324706890355614"),
		Y: *ba.NewElement("6717446314608317454056612988521276523143603352262745009529835803932138303462642316467740443074785130100608444461459148229179290796669940701932233012187852232981798195344309857014515889020782044489099447799956729215609170567055537"),
	}

	return &G2{
		api:        api,
		curveF:     ba,
		fr:         fr,
		w:          w,
		eigenvalue: eigenvalue,
		// GLV+FakeGLV precomputed values
		g2Gen:      g2Gen,
		g2GenNbits: g2GenNbits,
	}, nil
}

func (g2 *G2) phi(q *G2Affine) *G2Affine {
	x := g2.curveF.Mul(&q.P.X, g2.w)

	return &G2Affine{
		P: g2AffP{
			X: *x,
			Y: q.P.Y,
		},
	}
}

// scalarMulBySeed computes the [x₀]q where x₀=9586122913090633729 is the seed of the curve.
func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {
	z := g2.triple(q)
	z = g2.doubleAndAdd(z, q)
	t0 := g2.double(z)
	t0 = g2.double(t0)
	z = g2.add(z, t0)
	t1 := g2.triple(z)
	t0 = g2.add(t0, t1)
	t0 = g2.doubleN(t0, 9)
	z = g2.doubleAndAdd(t0, z)
	z = g2.doubleN(z, 45)
	z = g2.doubleAndAdd(z, q)

	return z
}

func (g2 G2) add(p, q *G2Affine) *G2Affine {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g2.curveF.Sub(&q.P.Y, &p.P.Y)
	qxpx := g2.curveF.Sub(&q.P.X, &p.P.X)
	λ := g2.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	mone := g2.curveF.NewElement(-1)
	xr := g2.curveF.Eval([][]*baseEl{{λ, λ}, {mone, &p.P.X}, {mone, &q.P.X}}, []int{1, 1, 1})

	// p.y = λ(p.x-r.x) - p.y
	yr := g2.curveF.Eval([][]*baseEl{{λ, &p.P.X}, {mone, λ, xr}, {mone, &p.P.Y}}, []int{1, 1, 1})

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

func (g2 G2) neg(p *G2Affine) *G2Affine {
	xr := &p.P.X
	yr := g2.curveF.Neg(&p.P.Y)
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
	// compute λ = (3p.x²)/2*p.y
	xx3a := g2.curveF.Mul(&p.P.X, &p.P.X)
	xx3a = g2.curveF.MulConst(xx3a, big.NewInt(3))
	y2 := g2.curveF.MulConst(&p.P.Y, big.NewInt(2))
	λ := g2.curveF.Div(xx3a, y2)

	// xr = λ²-2p.x
	mone := g2.curveF.NewElement(-1)
	xr := g2.curveF.Eval([][]*baseEl{{λ, λ}, {mone, &p.P.X}}, []int{1, 2})

	// yr = λ(p.x-xr) - p.y
	yr := g2.curveF.Eval([][]*baseEl{{λ, &p.P.X}, {mone, λ, xr}, {mone, &p.P.Y}}, []int{1, 1, 1})

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

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.curveF.Sub(&q.P.Y, &p.P.Y)
	xqxp := g2.curveF.Sub(&q.P.X, &p.P.X)
	λ1 := g2.curveF.Div(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	mone := g2.curveF.NewElement(-1)
	x2 := g2.curveF.Eval([][]*baseEl{{λ1, λ1}, {mone, &p.P.X}, {mone, &q.P.X}}, []int{1, 1, 1})

	// omit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := g2.curveF.Add(&p.P.Y, &p.P.Y)
	x2xp := g2.curveF.Sub(x2, &p.P.X)
	λ2 := g2.curveF.Div(ypyp, x2xp)
	λ2 = g2.curveF.Add(λ1, λ2)
	λ2 = g2.curveF.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	x3 := g2.curveF.Eval([][]*baseEl{{λ2, λ2}, {mone, &p.P.X}, {mone, x2}}, []int{1, 1, 1})

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.curveF.Eval([][]*baseEl{{λ2, &p.P.X}, {mone, λ2, x3}, {mone, &p.P.Y}}, []int{1, 1, 1})

	return &G2Affine{
		P: g2AffP{
			X: *x3,
			Y: *y3,
		},
	}
}

func (g2 G2) triple(p *G2Affine) *G2Affine {

	// compute λ = (3p.x²)/2*p.y
	xx := g2.curveF.Mul(&p.P.X, &p.P.X)
	xx = g2.curveF.MulConst(xx, big.NewInt(3))
	y2 := g2.curveF.MulConst(&p.P.Y, big.NewInt(2))
	λ1 := g2.curveF.Div(xx, y2)

	// xr = λ²-2p.x
	mone := g2.curveF.NewElement(-1)
	x2 := g2.curveF.Eval([][]*baseEl{{λ1, λ1}, {mone, &p.P.X}}, []int{1, 2})

	// omit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.curveF.Sub(&p.P.X, x2)
	λ2 := g2.curveF.Div(y2, x1x2)
	λ2 = g2.curveF.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	xr := g2.curveF.Eval([][]*baseEl{{λ2, λ2}, {mone, &p.P.X}, {mone, x2}}, []int{1, 1, 1})

	// yr = λ(p.x-xr) - p.y
	yr := g2.curveF.Eval([][]*baseEl{{λ2, &p.P.X}, {mone, λ2, xr}, {mone, &p.P.Y}}, []int{1, 1, 1})

	return &G2Affine{
		P: g2AffP{
			X: *xr,
			Y: *yr,
		},
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (g2 *G2) AssertIsEqual(p, q *G2Affine) {
	g2.curveF.AssertIsEqual(&p.P.X, &q.P.X)
	g2.curveF.AssertIsEqual(&p.P.Y, &q.P.Y)
}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (g2 *G2) Select(b frontend.Variable, p, q *G2Affine) *G2Affine {
	x := g2.curveF.Select(b, &p.P.X, &q.P.X)
	y := g2.curveF.Select(b, &p.P.Y, &q.P.Y)
	return &G2Affine{
		P:     g2AffP{X: *x, Y: *y},
		Lines: nil,
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
		addFn = g2.add // BW6-761 G2 doesn't have AddUnified, use add
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		selector = g2.api.And(g2.curveF.IsZero(&Q.P.X), g2.curveF.IsZero(&Q.P.Y))
		one := g2.curveF.One()
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
	negQY := g2.curveF.Neg(&Q.P.Y)
	tableQ[1] = &G2Affine{
		P: g2AffP{
			X: Q.P.X,
			Y: *g2.curveF.Select(selector1, negQY, &Q.P.Y),
		},
	}
	tableQ[0] = g2.neg(tableQ[1])
	// For BW6-761 G2, phi(Q) = (w * Q.X, Q.Y)
	phiQ := g2.phi(Q)
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: phiQ.P.X,
			Y: *g2.curveF.Select(selector2, negQY, &Q.P.Y),
		},
	}
	tablePhiQ[0] = g2.neg(tablePhiQ[1])
	tableQ[2] = g2.triple(tableQ[1])
	tablePhiQ[2] = &G2Affine{
		P: g2AffP{
			X: *g2.curveF.Mul(&tableQ[2].P.X, g2.w),
			Y: *g2.curveF.Select(selector2, g2.curveF.Neg(&tableQ[2].P.Y), &tableQ[2].P.Y),
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

	nbits := 190 // (377+1)/2 = 189, rounded up
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
				X: *g2.curveF.Mux(selectorX, &T6.P.X, &T10.P.X, &T14.P.X, &T2.P.X, &T7.P.X, &T11.P.X, &T15.P.X, &T3.P.X),
				Y: *g2.curveF.Mux(selectorY,
					&T6.P.Y, &T10.P.Y, &T14.P.Y, &T2.P.Y, &T7.P.Y, &T11.P.Y, &T15.P.Y, &T3.P.Y,
					&T8.P.Y, &T12.P.Y, &T16.P.Y, &T4.P.Y, &T5.P.Y, &T9.P.Y, &T13.P.Y, &T1.P.Y,
				),
			},
		}
		// Acc = [4]Acc + T
		Acc = g2.double(Acc)
		Acc = g2.doubleAndAdd(Acc, T)
	}

	// i = 0
	// subtract the Q, Φ(Q) if the first bits are 0.
	// When cfg.CompleteArithmetic is set, we use add.
	// This means when s=0 then Acc=(0,0).
	tableQ[0] = addFn(tableQ[0], Acc)
	Acc = g2.Select(s1bits[0], Acc, tableQ[0])
	tablePhiQ[0] = addFn(tablePhiQ[0], Acc)
	Acc = g2.Select(s2bits[0], Acc, tablePhiQ[0])

	if cfg.CompleteArithmetic {
		zero := g2.curveF.Zero()
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
	_, point, _, err := emulated.NewVarGenericHint(g2.api, 0, 2, 0, nil,
		[]*emulated.Element[BaseField]{&Q.P.X, &Q.P.Y},
		[]*emulated.Element[ScalarField]{s},
		scalarMulG2Hint)
	if err != nil {
		panic(fmt.Sprintf("scalarMulG2Hint: %v", err))
	}
	R := &G2Affine{
		P: g2AffP{
			X: *point[0],
			Y: *point[1],
		},
	}

	// handle (0,0)-point
	var _selector0 frontend.Variable
	_Q := Q
	if cfg.CompleteArithmetic {
		// if R=(0,0) we assign a dummy point
		one := g2.curveF.One()
		R = g2.Select(selector0, &G2Affine{P: g2AffP{X: *one, Y: *one}}, R)
		// if Q=(0,0) we assign a dummy point
		_selector0 = g2.api.And(g2.curveF.IsZero(&Q.P.X), g2.curveF.IsZero(&Q.P.Y))
		_Q = g2.Select(_selector0, &G2Affine{P: g2AffP{X: *one, Y: *one}}, Q)
	}

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]*G2Affine
	negQY := g2.curveF.Neg(&_Q.P.Y)
	tableQ[1] = &G2Affine{
		P: g2AffP{
			X: _Q.P.X,
			Y: *g2.curveF.Select(isNegu1, negQY, &_Q.P.Y),
		},
	}
	tableQ[0] = g2.neg(tableQ[1])
	// For BW6-761 G2, phi(Q) = (w * Q.X, Q.Y)
	tablePhiQ[1] = &G2Affine{
		P: g2AffP{
			X: *g2.curveF.Mul(&_Q.P.X, g2.w),
			Y: *g2.curveF.Select(isNegu2, negQY, &_Q.P.Y),
		},
	}
	tablePhiQ[0] = g2.neg(tablePhiQ[1])

	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]*G2Affine
	negRY := g2.curveF.Neg(&R.P.Y)
	tableR[1] = &G2Affine{
		P: g2AffP{
			X: R.P.X,
			Y: *g2.curveF.Select(isNegv1, negRY, &R.P.Y),
		},
	}
	tableR[0] = g2.neg(tableR[1])
	tablePhiR[1] = &G2Affine{
		P: g2AffP{
			X: *g2.curveF.Mul(&R.P.X, g2.w),
			Y: *g2.curveF.Select(isNegv2, negRY, &R.P.Y),
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
				X: *g2.curveF.Mux(selectorX,
					&B16.P.X, &B8.P.X, &B14.P.X, &B6.P.X, &B12.P.X, &B4.P.X, &B10.P.X, &B2.P.X,
				),
				Y: *g2.curveF.Mux(selectorY,
					&B16.P.Y, &B8.P.Y, &B14.P.Y, &B6.P.Y, &B12.P.Y, &B4.P.Y, &B10.P.Y, &B2.P.Y,
					&B15.P.Y, &B7.P.Y, &B13.P.Y, &B5.P.Y, &B11.P.Y, &B3.P.Y, &B9.P.Y, &B1.P.Y,
				),
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
		// if Q=(0,0) or s=0, skip the check
		skip := g2.api.Or(selector0, _selector0)
		Acc = g2.Select(skip, expected, Acc)
	}
	g2.AssertIsEqual(Acc, expected)

	if cfg.CompleteArithmetic {
		zeroEl := g2.curveF.Zero()
		R = g2.Select(selector0, &G2Affine{P: g2AffP{X: *zeroEl, Y: *zeroEl}}, R)
	}

	return R
}
