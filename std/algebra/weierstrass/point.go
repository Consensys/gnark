package weierstrass

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// New returns a new [Curve] instance over the base field Base and scalar field
// Scalars defined by the curve parameters params. It returns an error if
// initialising the field emulation fails (for example, when the native field is
// too small) or when the curve parameters are incompatible with the fields.
func New[Base, Scalars emulated.FieldParams](api frontend.API, params CurveParams) (*Curve[Base, Scalars], error) {
	ba, err := emulated.NewField[Base](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	sa, err := emulated.NewField[Scalars](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	Gx := emulated.ValueOf[Base](params.Gx)
	Gy := emulated.ValueOf[Base](params.Gy)
	return &Curve[Base, Scalars]{
		params:    params,
		api:       api,
		baseApi:   ba,
		scalarApi: sa,
		g: AffinePoint[Base]{
			X: Gx,
			Y: Gy,
		},
		a:    emulated.ValueOf[Base](params.A),
		addA: params.A.Cmp(big.NewInt(0)) != 0,
	}, nil
}

// Curve is an initialised curve which allows performing group operations.
type Curve[Base, Scalars emulated.FieldParams] struct {
	// params is the parameters of the curve
	params CurveParams
	// api is the native api, we construct it ourselves to be sure
	api frontend.API
	// baseApi is the api for point operations
	baseApi *emulated.Field[Base]
	// scalarApi is the api for scalar operations
	scalarApi *emulated.Field[Scalars]

	// g is the generator (base point) of the curve.
	g AffinePoint[Base]

	a    emulated.Element[Base]
	addA bool
}

// Generator returns the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) Generator() *AffinePoint[B] {
	return &c.g
}

// AffinePoint represents a point on the elliptic curve. We do not check that
// the point is actually on the curve.
type AffinePoint[Base emulated.FieldParams] struct {
	X, Y emulated.Element[Base]
}

// Neg returns an inverse of p. It doesn't modify p.
func (c *Curve[B, S]) Neg(p *AffinePoint[B]) *AffinePoint[B] {
	return &AffinePoint[B]{
		X: p.X,
		Y: *c.baseApi.Neg(&p.Y),
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (c *Curve[B, S]) AssertIsEqual(p, q *AffinePoint[B]) {
	c.baseApi.AssertIsEqual(&p.X, &q.X)
	c.baseApi.AssertIsEqual(&p.Y, &q.Y)
}

// Add adds q and r and returns it.
func (c *Curve[B, S]) Add(q, r *AffinePoint[B]) *AffinePoint[B] {
	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	p1ypy := c.baseApi.Sub(&r.Y, &q.Y)
	p1xpx := c.baseApi.Sub(&r.X, &q.X)
	lambda := c.baseApi.Div(p1ypy, p1xpx)

	// xr = lambda**2-p.x-p1.x
	lambdaSq := c.baseApi.MulMod(lambda, lambda)
	qxrx := c.baseApi.Add(&q.X, &r.X)
	xr := c.baseApi.Sub(lambdaSq, qxrx)

	// p.y = lambda(p.x-xr) - p.y
	pxxr := c.baseApi.Sub(&q.X, xr)
	lpxxr := c.baseApi.MulMod(lambda, pxxr)
	py := c.baseApi.Sub(lpxxr, &q.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(py),
	}
}

// Double doubles p and return it. It doesn't modify p.
func (c *Curve[B, S]) Double(p *AffinePoint[B]) *AffinePoint[B] {

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	xSq3a := c.baseApi.MulMod(&p.X, &p.X)
	xSq3a = c.baseApi.MulConst(xSq3a, big.NewInt(3))
	if c.addA {
		xSq3a = c.baseApi.Add(xSq3a, &c.a)
	}
	y2 := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	lambda := c.baseApi.Div(xSq3a, y2)

	// xr = lambda**2-p1.x-p1.x
	x2 := c.baseApi.MulConst(&p.X, big.NewInt(2))
	lambdaSq := c.baseApi.MulMod(lambda, lambda)
	xr := c.baseApi.Sub(lambdaSq, x2)

	// p.y = lambda(p.x-xr) - p.y
	pxxr := c.baseApi.Sub(&p.X, xr)
	lpxxr := c.baseApi.MulMod(lambda, pxxr)
	py := c.baseApi.Sub(lpxxr, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(py),
	}
}

// Select selects between p and q given the selector b. If b == 0, then returns
// p and q otherwise.
func (c *Curve[B, S]) Select(b frontend.Variable, p, q *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Select(b, &p.X, &q.X)
	y := c.baseApi.Select(b, &p.Y, &q.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// ScalarMul computes s * p and returns it. It doesn't modify p nor s.
func (c *Curve[B, S]) ScalarMul(p *AffinePoint[B], s *emulated.Element[S]) *AffinePoint[B] {
	res := p
	acc := c.Double(p)

	var st S
	sr := c.scalarApi.Reduce(s)
	sBits := c.scalarApi.ToBits(sr)
	for i := 1; i < st.Modulus().BitLen(); i++ {
		tmp := c.Add(res, acc)
		res = c.Select(sBits[i], tmp, res)
		acc = c.Double(acc)
	}

	tmp := c.Add(res, c.Neg(p))
	res = c.Select(sBits[0], res, tmp)
	return res
}
