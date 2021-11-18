/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package twistededwards

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Point point on a twisted Edwards curve in a Snark cs
type Point struct {
	X, Y frontend.Variable
}

// MustBeOnCurve checks if a point is on the reduced twisted Edwards curve
// a*x^2 + y^2 = 1 + d*x^2*y^2.
func (p *Point) MustBeOnCurve(api frontend.API, curve EdCurve) {

	one := big.NewInt(1)

	xx := api.Mul(p.X, p.X)
	yy := api.Mul(p.Y, p.Y)
	axx := api.Mul(xx, &curve.A)
	lhs := api.Add(axx, yy)

	dxx := api.Mul(xx, &curve.D)
	dxxyy := api.Mul(dxx, yy)
	rhs := api.Add(dxxyy, one)

	api.AssertIsEqual(lhs, rhs)

}

// AddFixedPoint Adds two points, among which is one fixed point (the base), on a twisted edwards curve (eg jubjub)
// p1, base, ecurve are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddFixedPoint(api frontend.API, p1 *Point /*basex*/, x /*basey*/, y interface{}, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := api.Mul(p1.X, y)
	n12 := api.Mul(p1.Y, x)
	n1 := api.Add(n11, n12)

	n21 := api.Mul(p1.Y, y)
	n22 := api.Mul(p1.X, x)
	an22 := api.Mul(n22, &curve.A)
	n2 := api.Sub(n21, an22)

	d11 := api.Mul(curve.D, n11, n12)
	d1 := api.Add(1, d11)
	d2 := api.Sub(1, d11)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// AddGeneric Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddGeneric(api frontend.API, p1, p2 *Point, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := api.Mul(p1.X, p2.Y)
	n12 := api.Mul(p1.Y, p2.X)
	n1 := api.Add(n11, n12)

	n21 := api.Mul(p1.Y, p2.Y)
	n22 := api.Mul(p1.X, p2.X)
	an22 := api.Mul(n22, &curve.A)
	n2 := api.Sub(n21, an22)

	d11 := api.Mul(curve.D, n11, n12)
	d1 := api.Add(1, d11)

	d2 := api.Sub(1, d11)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// Double doubles a points in SNARK coordinates
func (p *Point) Double(api frontend.API, p1 *Point, curve EdCurve) *Point {

	u := api.Mul(p1.X, p1.Y)
	v := api.Mul(p1.X, p1.X)
	w := api.Mul(p1.Y, p1.Y)
	z := api.Mul(v, w)

	n1 := api.Mul(2, u)
	av := api.Mul(v, &curve.A)
	n2 := api.Sub(w, av)
	d := api.Mul(z, curve.D)
	d1 := api.Add(1, d)
	d2 := api.Sub(1, d)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// ScalarMulNonFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulNonFixedBase(api frontend.API, p1 *Point, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := api.ToBinary(scalar)

	res := Point{
		0,
		1,
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(api, &res, curve)
		tmp := Point{}
		tmp.AddGeneric(api, &res, p1, curve)
		res.X = api.Select(b[i], tmp.X, res.X)
		res.Y = api.Select(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y
	return p
}

// ScalarMulFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// x, y: coordinates of the base point
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulFixedBase(api frontend.API, x, y interface{}, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := api.ToBinary(scalar)

	res := Point{
		0,
		1,
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(api, &res, curve)
		tmp := Point{}
		tmp.AddFixedPoint(api, &res, x, y, curve)
		res.X = api.Select(b[i], tmp.X, res.X)
		res.Y = api.Select(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// Neg computes the negative of a point in SNARK coordinates
func (p *Point) Neg(api frontend.API, p1 *Point) *Point {
	p.X = api.Neg(p1.X)
	p.Y = p1.Y
	return p
}
