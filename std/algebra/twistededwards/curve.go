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
	p.Add(c.api, &p1, &p2, c.params)
	return p
}

func (c *curve) Double(p1 Point) Point {
	var p Point
	p.Double(c.api, &p1, c.params)
	return p
}
func (c *curve) Neg(p1 Point) Point {
	var p Point
	p.Neg(c.api, &p1)
	return p
}
func (c *curve) AssertIsOnCurve(p1 Point) {
	p1.AssertIsOnCurve(c.api, c.params)
}
func (c *curve) ScalarMul(p1 Point, scalar frontend.Variable) Point {
	var p Point
	if c.endo != nil {
		// scalar mul glv
		p.scalarMulGLV(c.api, &p1, scalar, c.params, c.endo)
	} else {
		p.ScalarMul(c.api, &p1, scalar, c.params)
	}
	return p
}
func (c *curve) DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point {
	var p Point
	p.DoubleBaseScalarMul(c.api, &p1, &p2, s1, s2, c.params)
	return p
}
