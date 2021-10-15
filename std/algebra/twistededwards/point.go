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
// -x^2 + y^2 = 1 + d*x^2*y^2.
func (p *Point) MustBeOnCurve(gnark frontend.API, curve EdCurve) {

	one := big.NewInt(1)

	xx := gnark.Mul(p.X, p.X)
	yy := gnark.Mul(p.Y, p.Y)
	lhs := gnark.Sub(yy, xx)

	dxx := gnark.Mul(xx, &curve.D)
	dxxyy := gnark.Mul(dxx, yy)
	rhs := gnark.Add(dxxyy, one)

	gnark.AssertIsEqual(lhs, rhs)

}

// AddFixedPoint Adds two points, among which is one fixed point (the base), on a twisted edwards curve (eg jubjub)
// p1, base, ecurve are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddFixedPoint(gnark frontend.API, p1 *Point /*basex*/, x /*basey*/, y interface{}, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := gnark.Mul(p1.X, y)
	n12 := gnark.Mul(p1.Y, x)
	n1 := gnark.Add(n11, n12)

	n21 := gnark.Mul(p1.Y, y)
	n22 := gnark.Mul(p1.X, x)
	n2 := gnark.Add(n21, n22) // y**2-a*x**2, here we use a=-1

	d11 := gnark.Mul(curve.D, x, y, p1.X, p1.Y)
	d1 := gnark.Add(1, d11)
	d2 := gnark.Sub(1, d11)

	p.X = gnark.Div(n1, d1)
	p.Y = gnark.Div(n2, d2)

	return p
}

// AddGeneric Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddGeneric(gnark frontend.API, p1, p2 *Point, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := gnark.Mul(p1.X, p2.Y)
	n12 := gnark.Mul(p1.Y, p2.X)
	n1 := gnark.Add(n11, n12)

	n21 := gnark.Mul(p1.Y, p2.Y)
	n22 := gnark.Mul(p1.X, p2.X)
	n2 := gnark.Add(n21, n22) // y**2-a*x**2, here we use a=-1

	d11 := gnark.Mul(curve.D, p2.X, p2.Y, p1.X, p1.Y)
	d1 := gnark.Add(1, d11)

	d2 := gnark.Sub(1, d11)

	p.X = gnark.Div(n1, d1)
	p.Y = gnark.Div(n2, d2)

	return p
}

// Double doubles a points in SNARK coordinates
// IMPORTANT: it assumes the twisted Edwards is reduced (a=-1)
func (p *Point) Double(gnark frontend.API, p1 *Point, curve EdCurve) *Point {

	u := gnark.Mul(p1.X, p1.Y)
	v := gnark.Mul(p1.X, p1.X)
	w := gnark.Mul(p1.Y, p1.Y)
	z := gnark.Mul(v, w) // x**2*y**2

	n1 := gnark.Mul(2, u)
	n2 := gnark.Add(v, w)
	d := gnark.Mul(z, curve.D)
	d1 := gnark.Add(1, d)
	d2 := gnark.Sub(1, d)

	p.X = gnark.Div(n1, d1)
	p.Y = gnark.Div(n2, d2)

	return p
}

// ScalarMulNonFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulNonFixedBase(gnark frontend.API, p1 *Point, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := gnark.ToBinary(scalar)

	res := Point{
		gnark.Constant(0),
		gnark.Constant(1),
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(gnark, &res, curve)
		tmp := Point{}
		tmp.AddGeneric(gnark, &res, p1, curve)
		res.X = gnark.Select(b[i], tmp.X, res.X)
		res.Y = gnark.Select(b[i], tmp.Y, res.Y)
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
func (p *Point) ScalarMulFixedBase(gnark frontend.API, x, y interface{}, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := gnark.ToBinary(scalar)

	res := Point{
		gnark.Constant(0),
		gnark.Constant(1),
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(gnark, &res, curve)
		tmp := Point{}
		tmp.AddFixedPoint(gnark, &res, x, y, curve)
		res.X = gnark.Select(b[i], tmp.X, res.X)
		res.Y = gnark.Select(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// Neg computes the negative of a point in SNARK coordinates
func (p *Point) Neg(gnark frontend.API, p1 *Point) *Point {
	p.X = gnark.Neg(p1.X)
	p.Y = p1.Y
	return p
}
