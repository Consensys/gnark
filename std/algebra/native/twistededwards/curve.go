package twistededwards

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
)

// curve curve is the default twisted edwards companion curve (defined on api.Curve().Fr)
type curve struct {
	api    frontend.API
	id     twistededwards.ID
	params *CurveParams
	endo   *EndoParams
}

func (c *curve) Params() *CurveParams {
	return c.params
}

func (c *curve) API() frontend.API {
	return c.api
}

func (c *curve) Endo() *EndoParams {
	return c.endo
}

func (c *curve) Add(p1, p2 Point) Point {
	var p Point
	p.add(c.api, &p1, &p2, c.params)
	return p
}

func (c *curve) Double(p1 Point) Point {
	var p Point
	p.double(c.api, &p1, c.params)
	return p
}
func (c *curve) Neg(p1 Point) Point {
	var p Point
	p.neg(c.api, &p1)
	return p
}
func (c *curve) AssertIsOnCurve(p1 Point) {
	p1.assertIsOnCurve(c.api, c.params)
}
func (c *curve) ScalarMul(p1 Point, scalar frontend.Variable) Point {
	var p Point
	if c.endo != nil {
		// TODO restore
		// this is disabled until this issue is solved https://github.com/ConsenSys/gnark/issues/268
		// p.scalarMulGLV(c.api, &p1, scalar, c.params, c.endo)
		p.scalarMul(c.api, &p1, scalar, c.params)
	} else {
		p.scalarMul(c.api, &p1, scalar, c.params)
	}
	return p
}
func (c *curve) DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point {
	var p Point
	p.doubleBaseScalarMul(c.api, &p1, &p2, s1, s2, c.params)
	return p
}
