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
	p.scalarMul(c.api, &p1, scalar, c.params, c.endo)
	return p
}

// DoubleBaseScalarMul computes s1*p1 + s2*p2 and returns the result.
// It uses the most efficient implementation available:
// - For curves with GLV endomorphism (Bandersnatch): 6-MSM with r^(1/3) bounds
// - For curves without endomorphism: hinted LogUp with √r bounds
//
// ⚠️  The scalars s1 and s2 must be nonzero and the points p1, p2 must not be
// the identity point (0,1). These optimized implementations do not handle edge cases.
func (c *curve) DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point {
	var p Point
	if c.endo != nil {
		p.doubleBaseScalarMul6MSMLogUp(c.api, &p1, &p2, s1, s2, c.params, c.endo)
	} else {
		p.doubleBaseScalarMul3MSMLogUp(c.api, &p1, &p2, s1, s2, c.params)
	}
	return p
}
