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
	endo   *EndoParams // non-nil iff the curve has a GLV endomorphism (Bandersnatch)
}

func (c *curve) Params() *CurveParams {
	return c.params
}

func (c *curve) API() frontend.API {
	return c.api
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
	p.scalarMul(c.api, &p1, scalar, c.params)
	return p
}

// DoubleBaseScalarMul computes s1*p1 + s2*p2. It is complete for all scalar
// inputs, including zero, and for identity points.
func (c *curve) DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point {
	var p Point
	p.doubleBaseScalarMul(c.api, &p1, &p2, s1, s2, c.params)
	return p
}

// DoubleBaseScalarMulNonZero computes s1*p1 + s2*p2 using the most efficient
// lattice-based MSM variant available for the curve:
//   - GLV-equipped curves (Bandersnatch): 6-MSM with r^(1/3)-bounded sub-scalars.
//   - non-GLV curves (Jubjub, BabyJubjub, edBLS12-377, edBW6-761): 3-MSM with
//     r^(2/3)-bounded sub-scalars and LogUp lookups.
//
// The scalars s1, s2 must be nonzero and p1, p2 must not be the TE identity
// (0, 1). Use DoubleBaseScalarMul for complete edge-case handling.
func (c *curve) DoubleBaseScalarMulNonZero(p1, p2 Point, s1, s2 frontend.Variable) Point {
	var p Point
	if c.endo != nil {
		p.doubleBaseScalarMul6MSMLogUp(c.api, &p1, &p2, s1, s2, c.params, c.endo)
	} else {
		p.doubleBaseScalarMul3MSMLogUp(c.api, &p1, &p2, s1, s2, c.params)
	}
	return p
}
