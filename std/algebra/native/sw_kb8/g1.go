package sw_kb8

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/kb8"
	kbfp "github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_kb8"
	"github.com/consensys/gnark/std/algebra/native/maptocurve_kb8"
)

// Curve exposes kb8 point operations in circuits over the KoalaBear field.
type Curve struct {
	api frontend.API
}

var (
	curveA, curveB, accumulatorOffset = func() (E8, E8, G1Affine) {
		a, b := kb8.CurveCoefficients()
		_, offsetNative := kb8.Generators()
		return fields_kb8.NewE8(a), fields_kb8.NewE8(b), NewG1Affine(offsetNative)
	}()
)

func fromMapE2(v maptocurve_kb8.E2) E2 {
	return E2{A0: v.A0, A1: v.A1}
}

func fromMapE4(v maptocurve_kb8.E4) E4 {
	return E4{
		B0: fromMapE2(v.B0),
		B1: fromMapE2(v.B1),
	}
}

func fromMapE8(v maptocurve_kb8.E8) E8 {
	return E8{
		C0: fromMapE4(v.C0),
		C1: fromMapE4(v.C1),
	}
}

func fromMapPoint(v maptocurve_kb8.G1Affine) G1Affine {
	return G1Affine{
		X: fromMapE8(v.X),
		Y: fromMapE8(v.Y),
	}
}

// NewCurve initializes a new kb8 curve gadget.
func NewCurve(api frontend.API) (*Curve, error) {
	if api.Compiler().Field().Cmp(kbfp.Modulus()) != 0 {
		return nil, errors.New("expected KoalaBear native field for kb8 operations")
	}
	return &Curve{api: api}, nil
}

// Infinity returns the point at infinity represented as (0,0).
func (c *Curve) Infinity() G1Affine {
	var z E8
	z.SetZero()
	return G1Affine{X: z, Y: z}
}

// Neg outputs -p1.
func (p *G1Affine) Neg(api frontend.API, p1 G1Affine) *G1Affine {
	p.X = p1.X
	p.Y.Neg(api, p1.Y)
	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it.
func (p *G1Affine) Select(api frontend.API, b frontend.Variable, p1, p2 G1Affine) *G1Affine {
	p.X.Select(api, b, p1.X, p2.X)
	p.Y.Select(api, b, p1.Y, p2.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas and returns p.
func (p *G1Affine) AddAssign(api frontend.API, p1 G1Affine) *G1Affine {
	var dx, dy, lambda, xr, yr E8
	dx.Sub(api, p1.X, p.X)
	dy.Sub(api, p1.Y, p.Y)
	lambda.DivUnchecked(api, dy, dx)
	xr.Square(api, lambda)
	xr.Sub(api, xr, p.X)
	xr.Sub(api, xr, p1.X)
	yr.Sub(api, p.X, xr)
	yr.Mul(api, lambda, yr)
	yr.Sub(api, yr, p.Y)
	p.X = xr
	p.Y = yr
	return p
}

// Double doubles p1 in affine coordinates and returns p.
func (p *G1Affine) Double(api frontend.API, p1 G1Affine) *G1Affine {
	var twoY, num, lambda, xr, yr, den, one E8
	twoY.MulByFp(api, p1.Y, 2)
	yIsZero := twoY.IsZero(api)
	one.SetOne()
	den.Select(api, yIsZero, one, twoY)
	num.Square(api, p1.X)
	num.MulByFp(api, num, 3)
	num.Add(api, num, curveA)
	lambda.DivUnchecked(api, num, den)
	xr.Square(api, lambda)
	xr.Sub(api, xr, *new(E8).MulByFp(api, p1.X, 2))
	yr.Sub(api, p1.X, xr)
	yr.Mul(api, lambda, yr)
	yr.Sub(api, yr, p1.Y)
	var inf, res G1Affine
	inf.X.SetZero()
	inf.Y.SetZero()
	res = G1Affine{X: xr, Y: yr}
	p.Select(api, yIsZero, inf, res)
	return p
}

// AddUnified adds q to p and handles infinity, doubling, and opposite points.
func (p *G1Affine) AddUnified(api frontend.API, q G1Affine) *G1Affine {
	selector1 := api.And(p.X.IsZero(api), p.Y.IsZero(api))
	selector2 := api.And(q.X.IsZero(api), q.Y.IsZero(api))
	var pxqx, pxplusqx, num, den, one, lambda, xr, yr E8
	pxqx.Mul(api, p.X, q.X)
	pxplusqx.Add(api, p.X, q.X)
	num.Square(api, pxplusqx)
	num.Sub(api, num, pxqx)
	num.Add(api, num, curveA)
	den.Add(api, p.Y, q.Y)
	selector3 := den.IsZero(api)
	one.SetOne()
	den.Select(api, selector3, one, den)
	lambda.DivUnchecked(api, num, den)
	xr.Square(api, lambda)
	xr.Sub(api, xr, pxplusqx)
	yr.Sub(api, p.X, xr)
	yr.Mul(api, lambda, yr)
	yr.Sub(api, yr, p.Y)
	result := G1Affine{X: xr, Y: yr}

	var inf G1Affine
	inf.X.SetZero()
	inf.Y.SetZero()
	result.Select(api, selector1, q, result)
	result.Select(api, selector2, *p, result)
	result.Select(api, selector3, inf, result)

	p.X = result.X
	p.Y = result.Y
	return p
}

// AddBrierJoye adds q to p using the Brier-Joye/Joye unified affine formula.
// It assumes neither operand is infinity and maps opposite points to infinity.
// Doubling is handled by the same formula.
func (p *G1Affine) AddBrierJoye(api frontend.API, q G1Affine) *G1Affine {
	var pxqx, pxplusqx, num, den, one, lambda, xr, yr E8
	pxqx.Mul(api, p.X, q.X)
	pxplusqx.Add(api, p.X, q.X)
	num.Square(api, pxplusqx)
	num.Sub(api, num, pxqx)
	num.Add(api, num, curveA)
	den.Add(api, p.Y, q.Y)
	selector := den.IsZero(api)
	one.SetOne()
	den.Select(api, selector, one, den)
	lambda.DivUnchecked(api, num, den)
	xr.Square(api, lambda)
	xr.Sub(api, xr, pxplusqx)
	yr.Sub(api, p.X, xr)
	yr.Mul(api, lambda, yr)
	yr.Sub(api, yr, p.Y)
	result := G1Affine{X: xr, Y: yr}

	var inf G1Affine
	inf.X.SetZero()
	inf.Y.SetZero()
	result.Select(api, selector, inf, result)
	p.X = result.X
	p.Y = result.Y
	return p
}

// DoubleAndAdd computes 2*p1+p2 in affine coordinates and returns p.
func (p *G1Affine) DoubleAndAdd(api frontend.API, p1, p2 *G1Affine) *G1Affine {
	var dx, dy, l1, x3, den2, l2, x4, y4 E8
	dx.Sub(api, p1.X, p2.X)
	dy.Sub(api, p1.Y, p2.Y)
	l1.DivUnchecked(api, dy, dx)

	x3.Square(api, l1)
	x3.Sub(api, x3, p1.X)
	x3.Sub(api, x3, p2.X)

	den2.Sub(api, x3, p1.X)
	l2.MulByFp(api, p1.Y, 2)
	l2.DivUnchecked(api, l2, den2)
	l2.Add(api, l2, l1)

	x4.Square(api, l2)
	x4.Sub(api, x4, p1.X)
	x4.Sub(api, x4, x3)

	y4.Sub(api, x4, p1.X)
	y4.Mul(api, y4, l2)
	y4.Sub(api, y4, p1.Y)

	p.X = x4
	p.Y = y4
	return p
}

// AssertIsEqual asserts equality of two points.
func (c *Curve) AssertIsEqual(p, q *G1Affine) {
	p.X.AssertIsEqual(c.api, q.X)
	p.Y.AssertIsEqual(c.api, q.Y)
}

func (c *Curve) isInfinity(p *G1Affine) frontend.Variable {
	return c.api.And(p.X.IsZero(c.api), p.Y.IsZero(c.api))
}

// AssertIsOnCurve asserts that p is infinity or lies on kb8.
func (c *Curve) AssertIsOnCurve(p *G1Affine) {
	isInf := c.isInfinity(p)
	left := *new(E8).Square(c.api, p.Y)
	right := *new(E8).Cube(c.api, p.X)
	right.Sub(c.api, right, *new(E8).MulByFp(c.api, p.X, 3))
	right.Add(c.api, right, curveB)
	diff := *new(E8).Sub(c.api, left, right)
	isCurve := diff.IsZero(c.api)
	c.api.AssertIsEqual(c.api.Or(isInf, isCurve), 1)
}

// AssertIsInSubGroup asserts subgroup membership. kb8 has prime order, so this
// is equivalent to the on-curve check.
func (c *Curve) AssertIsInSubGroup(p *G1Affine) {
	c.AssertIsOnCurve(p)
}
