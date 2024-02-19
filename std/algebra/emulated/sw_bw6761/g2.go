package sw_bw6761

import (
	"fmt"
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
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
	curveF *emulated.Field[BaseField]
	w      *emulated.Element[BaseField]
}

func NewG2(api frontend.API) (*G2, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	w := emulated.ValueOf[BaseField]("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648")
	return &G2{
		curveF: ba,
		w:      &w,
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
	λλ := g2.curveF.Mul(λ, λ)
	qxpx = g2.curveF.Add(&p.P.X, &q.P.X)
	xr := g2.curveF.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := g2.curveF.Sub(&p.P.X, xr)
	λpxrx := g2.curveF.Mul(λ, pxrx)
	yr := g2.curveF.Sub(λpxrx, &p.P.Y)

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
	x2 := g2.curveF.MulConst(&p.P.X, big.NewInt(2))
	λλ := g2.curveF.Mul(λ, λ)
	xr := g2.curveF.Sub(λλ, x2)

	// yr = λ(p-xr) - p.y
	pxrx := g2.curveF.Sub(&p.P.X, xr)
	λpxrx := g2.curveF.Mul(λ, pxrx)
	yr := g2.curveF.Sub(λpxrx, &p.P.Y)

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
	λ1λ1 := g2.curveF.Mul(λ1, λ1)
	xqxp = g2.curveF.Add(&p.P.X, &q.P.X)
	x2 := g2.curveF.Sub(λ1λ1, xqxp)

	// ommit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := g2.curveF.Add(&p.P.Y, &p.P.Y)
	x2xp := g2.curveF.Sub(x2, &p.P.X)
	λ2 := g2.curveF.Div(ypyp, x2xp)
	λ2 = g2.curveF.Add(λ1, λ2)
	λ2 = g2.curveF.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	λ2λ2 := g2.curveF.Mul(λ2, λ2)
	x3 := g2.curveF.Sub(λ2λ2, &p.P.X)
	x3 = g2.curveF.Sub(x3, x2)

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.curveF.Sub(&p.P.X, x3)
	y3 = g2.curveF.Mul(λ2, y3)
	y3 = g2.curveF.Sub(y3, &p.P.Y)

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
	x2 := g2.curveF.MulConst(&p.P.X, big.NewInt(2))
	λ1λ1 := g2.curveF.Mul(λ1, λ1)
	x2 = g2.curveF.Sub(λ1λ1, x2)

	// ommit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.curveF.Sub(&p.P.X, x2)
	λ2 := g2.curveF.Div(y2, x1x2)
	λ2 = g2.curveF.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	λ2λ2 := g2.curveF.Mul(λ2, λ2)
	qxrx := g2.curveF.Add(x2, &p.P.X)
	xr := g2.curveF.Sub(λ2λ2, qxrx)

	// yr = λ(p.x-xr) - p.y
	pxrx := g2.curveF.Sub(&p.P.X, xr)
	λ2pxrx := g2.curveF.Mul(λ2, pxrx)
	yr := g2.curveF.Sub(λ2pxrx, &p.P.Y)

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
