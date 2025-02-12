package sw_bls12381

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[BaseField]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[ScalarField]

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bls12381.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

type G1 struct {
	curveF *emulated.Field[BaseField]
	w      *emulated.Element[BaseField]
}

func NewG1(api frontend.API) (*G1, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	w := emulated.ValueOf[BaseField]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	return &G1{
		curveF: ba,
		w:      &w,
	}, nil
}

func (g1 *G1) phi(q *G1Affine) *G1Affine {
	x := g1.curveF.Mul(&q.X, g1.w)

	return &G1Affine{
		X: *x,
		Y: q.Y,
	}
}

func (g1 *G1) double(p *G1Affine) *G1Affine {
	mone := g1.curveF.NewElement(-1)
	// compute λ = (3p.x²)/2*p.y
	xx3a := g1.curveF.Mul(&p.X, &p.X)
	xx3a = g1.curveF.MulConst(xx3a, big.NewInt(3))
	y1 := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	λ := g1.curveF.Div(xx3a, y1)

	// xr = λ²-2p.x
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {mone, &p.X}}, []int{1, 2})

	// yr = λ(p-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, g1.curveF.Sub(&p.X, xr)}, {mone, &p.Y}}, []int{1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) doubleN(p *G1Affine, n int) *G1Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g1.double(pn)
	}
	return pn
}

func (g1 G1) add(p, q *G1Affine) *G1Affine {
	mone := g1.curveF.NewElement(-1)
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g1.curveF.Sub(&q.Y, &p.Y)
	qxpx := g1.curveF.Sub(&q.X, &p.X)
	λ := g1.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {mone, g1.curveF.Add(&p.X, &q.X)}}, []int{1, 1})

	// p.y = λ(p.x-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, g1.curveF.Sub(&p.X, xr)}, {mone, &p.Y}}, []int{1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 G1) doubleAndAdd(p, q *G1Affine) *G1Affine {

	mone := g1.curveF.NewElement(-1)
	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g1.curveF.Sub(&q.Y, &p.Y)
	xqxp := g1.curveF.Sub(&q.X, &p.X)
	λ1 := g1.curveF.Div(yqyp, xqxp)

	// compute x1 = λ1²-p.x-q.x
	x2 := g1.curveF.Eval([][]*baseEl{{λ1, λ1}, {mone, g1.curveF.Add(&p.X, &q.X)}}, []int{1, 1})

	// omit y2 computation

	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	x2xp := g1.curveF.Sub(x2, &p.X)
	λ2 := g1.curveF.Div(ypyp, x2xp)
	λ2 = g1.curveF.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x3 := g1.curveF.Eval([][]*baseEl{{λ2, λ2}, {mone, &p.X}, {mone, x2}}, []int{1, 1, 1})

	// compute y3 = -λ2*(x3- p.x)-p.y
	y3 := g1.curveF.Eval([][]*baseEl{{λ2, g1.curveF.Sub(x3, &p.X)}, {mone, &p.Y}}, []int{1, 1})

	return &G1Affine{
		X: *x3,
		Y: *y3,
	}
}

func (g1 *G1) scalarMulBySeedSquare(q *G1Affine) *G1Affine {
	z := g1.double(q)
	z = g1.add(q, z)
	z = g1.double(z)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 2)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 8)
	z = g1.doubleAndAdd(z, q)
	t0 := g1.double(z)
	t0 = g1.add(z, t0)
	t0 = g1.double(t0)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 2)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 8)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 31)
	z = g1.add(t0, z)
	z = g1.doubleN(z, 32)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 32)

	return z
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bls12381.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// ScalarField is the [emulated.FieldParams] implementation of the curve scalar field.
type ScalarField = emulated.BLS12381Fr

// BaseField is the [emulated.FieldParams] implementation of the curve base field.
type BaseField = emulated.BLS12381Fp
