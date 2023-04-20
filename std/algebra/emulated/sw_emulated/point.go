package sw_emulated

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
	emuGm := make([]AffinePoint[Base], len(params.Gm))
	for i, v := range params.Gm {
		emuGm[i] = AffinePoint[Base]{emulated.ValueOf[Base](v[0]), emulated.ValueOf[Base](v[1])}
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
		gm:   emuGm,
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

	// gm are the pre-computed multiples the generator (base point) of the curve.
	gm []AffinePoint[Base]

	a    emulated.Element[Base]
	addA bool
}

// Generator returns the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) Generator() *AffinePoint[B] {
	return &c.g
}

// GeneratorMultiples returns the pre-computed multiples of the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) GeneratorMultiples() []AffinePoint[B] {
	return c.gm
}

// AffinePoint represents a point on the elliptic curve. We do not check that
// the point is actually on the curve.
//
// Point (0,0) represents point at the infinity. This representation is
// compatible with the EVM representations of points at infinity.
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

// add adds p and q and returns it. It doesn't modify p nor q.
//
// ⚠️  p must be different than q and -q, and both nonzero.
//
// It uses incomplete formulas in affine coordinates.
func (c *Curve[B, S]) add(p, q *AffinePoint[B]) *AffinePoint[B] {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := c.baseApi.Sub(&q.Y, &p.Y)
	qxpx := c.baseApi.Sub(&q.X, &p.X)
	λ := c.baseApi.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := c.baseApi.MulMod(λ, λ)
	qxpx = c.baseApi.Add(&p.X, &q.X)
	xr := c.baseApi.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := c.baseApi.Sub(&p.X, xr)
	λpxrx := c.baseApi.MulMod(λ, pxrx)
	yr := c.baseApi.Sub(λpxrx, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// AddUnified adds p and q and returns it. It doesn't modify p nor q.
//
// ✅ p can be equal to q, and either or both can be (0,0).
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It uses the unified formulas of Brier and Joye ([[BriJoy02]] (Corollary 1)).
//
// [BriJoy02]: https://link.springer.com/content/pdf/10.1007/3-540-45664-3_24.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (c *Curve[B, S]) AddUnified(p, q *AffinePoint[B]) *AffinePoint[B] {

	// selector1 = 1 when p is (0,0) and 0 otherwise
	selector1 := c.api.And(c.baseApi.IsZero(&p.X), c.baseApi.IsZero(&p.Y))
	// selector2 = 1 when q is (0,0) and 0 otherwise
	selector2 := c.api.And(c.baseApi.IsZero(&q.X), c.baseApi.IsZero(&q.Y))

	// λ = ((p.x+q.x)² - p.x*q.x + a)/(p.y + q.y)
	pxqx := c.baseApi.MulMod(&p.X, &q.X)
	pxplusqx := c.baseApi.Add(&p.X, &q.X)
	num := c.baseApi.MulMod(pxplusqx, pxplusqx)
	num = c.baseApi.Sub(num, pxqx)
	if c.addA {
		num = c.baseApi.Add(num, &c.a)
	}
	denum := c.baseApi.Add(&p.Y, &q.Y)
	// if p.y + q.y = 0, assign dummy 1 to denum and continue
	selector3 := c.baseApi.IsZero(denum)
	denum = c.baseApi.Select(selector3, c.baseApi.One(), denum)
	λ := c.baseApi.Div(num, denum)

	// x = λ^2 - p.x - q.x
	xr := c.baseApi.MulMod(λ, λ)
	xr = c.baseApi.Sub(xr, pxplusqx)

	// y = λ(p.x - xr) - p.y
	yr := c.baseApi.Sub(&p.X, xr)
	yr = c.baseApi.MulMod(yr, λ)
	yr = c.baseApi.Sub(yr, &p.Y)
	result := AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}

	zero := c.baseApi.Zero()
	infinity := AffinePoint[B]{X: *zero, Y: *zero}
	// if p=(0,0) return q
	result = *c.Select(selector1, q, &result)
	// if q=(0,0) return p
	result = *c.Select(selector2, p, &result)
	// if p.y + q.y = 0, return (0, 0)
	result = *c.Select(selector3, &infinity, &result)

	return &result
}

// double doubles p and return it. It doesn't modify p.
//
// ⚠️  p.Y must be nonzero.
//
// It uses affine coordinates.
func (c *Curve[B, S]) double(p *AffinePoint[B]) *AffinePoint[B] {

	// compute λ = (3p.x²+a)/2*p.y, here we assume a=0 (j invariant 0 curve)
	xx3a := c.baseApi.MulMod(&p.X, &p.X)
	xx3a = c.baseApi.MulConst(xx3a, big.NewInt(3))
	if c.addA {
		xx3a = c.baseApi.Add(xx3a, &c.a)
	}
	y2 := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	λ := c.baseApi.Div(xx3a, y2)

	// xr = λ²-2p.x
	x2 := c.baseApi.MulConst(&p.X, big.NewInt(2))
	λλ := c.baseApi.MulMod(λ, λ)
	xr := c.baseApi.Sub(λλ, x2)

	// yr = λ(p-xr) - p.y
	pxrx := c.baseApi.Sub(&p.X, xr)
	λpxrx := c.baseApi.MulMod(λ, pxrx)
	yr := c.baseApi.Sub(λpxrx, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// triple triples p and return it. It follows [ELM03] (Section 3.1).
// Saves the computation of the y coordinate of 2p as it is used only in the computation of λ2,
// which can be computed as
//
//	λ2 = -λ1-2*p.y/(x2-p.x)
//
// instead. It doesn't modify p.
//
// ⚠️  p.Y must be nonzero.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
func (c *Curve[B, S]) triple(p *AffinePoint[B]) *AffinePoint[B] {

	// compute λ1 = (3p.x²+a)/2p.y, here we assume a=0 (j invariant 0 curve)
	xx := c.baseApi.MulMod(&p.X, &p.X)
	xx = c.baseApi.MulConst(xx, big.NewInt(3))
	if c.addA {
		xx = c.baseApi.Add(xx, &c.a)
	}
	y2 := c.baseApi.MulConst(&p.Y, big.NewInt(2))
	λ1 := c.baseApi.Div(xx, y2)

	// xr = λ1²-2p.x
	x2 := c.baseApi.MulConst(&p.X, big.NewInt(2))
	λ1λ1 := c.baseApi.MulMod(λ1, λ1)
	x2 = c.baseApi.Sub(λ1λ1, x2)

	// ommit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := c.baseApi.Sub(&p.X, x2)
	λ2 := c.baseApi.Div(y2, x1x2)
	λ2 = c.baseApi.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	λ2λ2 := c.baseApi.MulMod(λ2, λ2)
	qxrx := c.baseApi.Add(x2, &p.X)
	xr := c.baseApi.Sub(λ2λ2, qxrx)

	// yr = λ(p.x-xr) - p.y
	pxrx := c.baseApi.Sub(&p.X, xr)
	λ2pxrx := c.baseApi.MulMod(λ2, pxrx)
	yr := c.baseApi.Sub(λ2pxrx, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(xr),
		Y: *c.baseApi.Reduce(yr),
	}
}

// doubleAndAdd computes 2p+q as (p+q)+p. It follows [ELM03] (Section 3.1)
// Saves the computation of the y coordinate of p+q as it is used only in the computation of λ2,
// which can be computed as
//
//	λ2 = -λ1-2*p.y/(x2-p.x)
//
// instead. It doesn't modify p nor q.
//
// ⚠️  p must be different than q and -q, and both nonzero.
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
func (c *Curve[B, S]) doubleAndAdd(p, q *AffinePoint[B]) *AffinePoint[B] {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := c.baseApi.Sub(&q.Y, &p.Y)
	xqxp := c.baseApi.Sub(&q.X, &p.X)
	λ1 := c.baseApi.Div(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	λ1λ1 := c.baseApi.MulMod(λ1, λ1)
	xqxp = c.baseApi.Add(&p.X, &q.X)
	x2 := c.baseApi.Sub(λ1λ1, xqxp)

	// ommit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := c.baseApi.Add(&p.Y, &p.Y)
	x2xp := c.baseApi.Sub(x2, &p.X)
	λ2 := c.baseApi.Div(ypyp, x2xp)
	λ2 = c.baseApi.Add(λ1, λ2)
	λ2 = c.baseApi.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	λ2λ2 := c.baseApi.MulMod(λ2, λ2)
	x3 := c.baseApi.Sub(λ2λ2, &p.X)
	x3 = c.baseApi.Sub(x3, x2)

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := c.baseApi.Sub(&p.X, x3)
	y3 = c.baseApi.Mul(λ2, y3)
	y3 = c.baseApi.Sub(y3, &p.Y)

	return &AffinePoint[B]{
		X: *c.baseApi.Reduce(x3),
		Y: *c.baseApi.Reduce(y3),
	}

}

// Select selects between p and q given the selector b. If b == 1, then returns
// p and q otherwise.
func (c *Curve[B, S]) Select(b frontend.Variable, p, q *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Select(b, &p.X, &q.X)
	y := c.baseApi.Select(b, &p.Y, &q.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// Lookup2 performs a 2-bit lookup between i0, i1, i2, i3 based on bits b0
// and b1. Returns:
//   - i0 if b0=0 and b1=0,
//   - i1 if b0=1 and b1=0,
//   - i2 if b0=0 and b1=1,
//   - i3 if b0=1 and b1=1.
func (c *Curve[B, S]) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 *AffinePoint[B]) *AffinePoint[B] {
	x := c.baseApi.Lookup2(b0, b1, &i0.X, &i1.X, &i2.X, &i3.X)
	y := c.baseApi.Lookup2(b0, b1, &i0.Y, &i1.Y, &i2.Y, &i3.Y)
	return &AffinePoint[B]{
		X: *x,
		Y: *y,
	}
}

// ScalarMul computes s * p and returns it. It doesn't modify p nor s.
//
// ✅ p can can be (0,0) and s can be 0.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It computes the standard little-endian variable-base double-and-add algorithm
// [HMV04] (Algorithm 3.26).
//
// Since we use incomplete formulas for the addition law, we need to start with
// a non-zero accumulator point (res). To do this, we skip the LSB (bit at
// position 0) and proceed assuming it was 1. At the end, we conditionally
// subtract the initial value (p) if LSB is 1. We also handle the bits at
// positions 1, n-2 and n-1 outside of the loop to optimize the number of
// constraints using [ELM03] (Section 3.1)
//
// [ELM03]: https://arxiv.org/pdf/math/0208038.pdf
// [HMV04]: https://link.springer.com/book/10.1007/b97644
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (c *Curve[B, S]) ScalarMul(p *AffinePoint[B], s *emulated.Element[S]) *AffinePoint[B] {

	// if p=(0,0) we assign a dummy (0,1) to p and continue
	selector := c.api.And(c.baseApi.IsZero(&p.X), c.baseApi.IsZero(&p.Y))
	one := c.baseApi.One()
	p = c.Select(selector, &AffinePoint[B]{X: *one, Y: *one}, p)

	var st S
	sr := c.scalarApi.Reduce(s)
	sBits := c.scalarApi.ToBits(sr)
	n := st.Modulus().BitLen()

	// i = 1
	tmp := c.triple(p)
	res := c.Select(sBits[1], tmp, p)
	acc := c.add(tmp, p)

	for i := 2; i <= n-3; i++ {
		tmp := c.add(res, acc)
		res = c.Select(sBits[i], tmp, res)
		acc = c.double(acc)
	}

	// i = n-2
	tmp = c.add(res, acc)
	res = c.Select(sBits[n-2], tmp, res)

	// i = n-1
	tmp = c.doubleAndAdd(acc, res)
	res = c.Select(sBits[n-1], tmp, res)

	// i = 0
	// we use AddUnified here instead of Add so that when s=0, res=(0,0)
	// because AddUnified(p, -p) = (0,0)
	tmp = c.AddUnified(res, c.Neg(p))
	res = c.Select(sBits[0], res, tmp)

	// if p=(0,0), return (0,0)
	zero := c.baseApi.Zero()
	res = c.Select(selector, &AffinePoint[B]{X: *zero, Y: *zero}, res)

	return res
}

// ScalarMulBase computes s * g and returns it, where g is the fixed generator.
// It doesn't modify s.
//
// ✅ When s=0, it returns (0,0).
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// It computes the standard little-endian fixed-base double-and-add algorithm
// [HMV04] (Algorithm 3.26).
//
// The method proceeds similarly to ScalarMul but with the points [2^i]g
// precomputed.  The bits at positions 1 and 2 are handled outside of the loop
// to optimize the number of constraints using a Lookup2 with pre-computed
// [3]g, [5]g and [7]g points.
//
// [HMV04]: https://link.springer.com/book/10.1007/b97644
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (c *Curve[B, S]) ScalarMulBase(s *emulated.Element[S]) *AffinePoint[B] {
	g := c.Generator()
	gm := c.GeneratorMultiples()

	var st S
	sr := c.scalarApi.Reduce(s)
	sBits := c.scalarApi.ToBits(sr)

	// i = 1, 2
	// gm[0] = 3g, gm[1] = 5g, gm[2] = 7g
	res := c.Lookup2(sBits[1], sBits[2], g, &gm[0], &gm[1], &gm[2])

	for i := 3; i < st.Modulus().BitLen(); i++ {
		// gm[i] = [2^i]g
		tmp := c.add(res, &gm[i])
		res = c.Select(sBits[i], tmp, res)
	}

	// i = 0
	tmp := c.AddUnified(res, c.Neg(g))
	res = c.Select(sBits[0], res, tmp)

	return res
}
