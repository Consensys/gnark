package twistededwards

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type jubjubCurve struct {
	api    frontend.API
	id     twistededwards.ID
	params *CurveParams
}

func (c *jubjubCurve) Params() *CurveParams {
	return c.params
}

func (c *jubjubCurve) Endo() *EndoParams {
	return nil
}

func (c *jubjubCurve) API() frontend.API {
	return c.api
}

func (c *jubjubCurve) Add(p1, p2 Point) Point {
	p := jubjubPoint{}
	p.Add(c.api, &jubjubPoint{Point{p1.X, p1.Y}}, &jubjubPoint{Point{p2.X, p2.Y}}, c.params)
	return p.Point
}

func (c *jubjubCurve) Double(p1 Point) Point {
	p := jubjubPoint{}
	p.Double(c.api, &jubjubPoint{Point{p1.X, p1.Y}}, c.params)
	return p.Point
}
func (c *jubjubCurve) Neg(p1 Point) Point {
	p := jubjubPoint{}
	p.Neg(c.api, &jubjubPoint{Point{p1.X, p1.Y}})
	return p.Point
}
func (c *jubjubCurve) AssertIsOnCurve(p1 Point) {
	p := jubjubPoint{Point: p1}
	p.AssertIsOnCurve(c.api, c.params)
}
func (c *jubjubCurve) ScalarMul(p1 Point, scalar frontend.Variable) Point {
	p := jubjubPoint{}
	p.ScalarMul(c.api, &jubjubPoint{Point{p1.X, p1.Y}}, scalar, c.params)
	return p.Point
}
func (c *jubjubCurve) DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point {
	p := jubjubPoint{}
	p.DoubleBaseScalarMul(c.api, &jubjubPoint{Point{p1.X, p1.Y}}, &jubjubPoint{Point{p2.X, p2.Y}}, s1, s2, c.params)
	return p.Point
}
