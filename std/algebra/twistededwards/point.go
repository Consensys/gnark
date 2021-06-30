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

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Point point on a twisted Edwards curve in a Snark cs
type Point struct {
	X, Y frontend.Variable
}

// MustBeOnCurve checks if a point is on the reduced twisted Edwards curve
// -x^2 + y^2 = 1 + d*x^2*y^2.
func (p *Point) MustBeOnCurve(cs *frontend.ConstraintSystem, curve EdCurve) {

	one := big.NewInt(1)

	xx := cs.Mul(p.X, p.X)
	yy := cs.Mul(p.Y, p.Y)
	lhs := cs.Sub(yy, xx)

	dxx := cs.Mul(xx, &curve.D)
	dxxyy := cs.Mul(dxx, yy)
	rhs := cs.Add(dxxyy, one)

	cs.AssertIsEqual(lhs, rhs)

}

// AddFixedPoint Adds two points, among which is one fixed point (the base), on a twisted edwards curve (eg jubjub)
// p1, base, ecurve are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddFixedPoint(cs *frontend.ConstraintSystem, p1 *Point /*basex*/, x /*basey*/, y interface{}, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := cs.Mul(p1.X, y)
	n12 := cs.Mul(p1.Y, x)
	n1 := cs.Add(n11, n12)

	n21 := cs.Mul(p1.Y, y)
	n22 := cs.Mul(p1.X, x)
	n2 := cs.Add(n21, n22) // y**2-a*x**2, here we use a=-1

	d11 := cs.Mul(curve.D, x, y, p1.X, p1.Y)
	d1 := cs.Add(1, d11)
	d2 := cs.Sub(1, d11)

	p.X = cs.Div(n1, d1)
	p.Y = cs.Div(n2, d2)

	return p
}

// AddGeneric Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddGeneric(cs *frontend.ConstraintSystem, p1, p2 *Point, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := cs.Mul(p1.X, p2.Y)
	n12 := cs.Mul(p1.Y, p2.X)
	n1 := cs.Add(n11, n12)

	n21 := cs.Mul(p1.Y, p2.Y)
	n22 := cs.Mul(p1.X, p2.X)
	n2 := cs.Add(n21, n22) // y**2-a*x**2, here we use a=-1

	d11 := cs.Mul(curve.D, p2.X, p2.Y, p1.X, p1.Y)
	d1 := cs.Add(1, d11)

	d2 := cs.Sub(1, d11)

	p.X = cs.Div(n1, d1)
	p.Y = cs.Div(n2, d2)

	return p
}

// Double doubles a points in SNARK coordinates
// IMPORTANT: it assumes the twisted Edwards is reduced (a=-1)
func (p *Point) Double(cs *frontend.ConstraintSystem, p1 *Point, curve EdCurve) *Point {

	u := cs.Mul(p1.X, p1.Y)
	v := cs.Mul(p1.X, p1.X)
	w := cs.Mul(p1.Y, p1.Y)
	z := cs.Mul(v, w) // x**2*y**2

	n1 := cs.Mul(2, u)
	n2 := cs.Add(v, w)
	d := cs.Mul(z, curve.D)
	d1 := cs.Add(1, d)
	d2 := cs.Sub(1, d)

	p.X = cs.Div(n1, d1)
	p.Y = cs.Div(n2, d2)

	return p
}

// ScalarMulNonFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulNonFixedBase(cs *frontend.ConstraintSystem, p1 *Point, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	// TODO handle this properly (put the size in curve struct probably)
	var frSize int
	if curve.ID == ecc.BW6_761 {
		frSize = 384
	} else {
		frSize = 256
	}
	b := cs.ToBinary(scalar, frSize)

	res := Point{
		cs.Constant(0),
		cs.Constant(1),
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(cs, &res, curve)
		tmp := Point{}
		tmp.AddGeneric(cs, &res, p1, curve)
		res.X = cs.Select(b[i], tmp.X, res.X)
		res.Y = cs.Select(b[i], tmp.Y, res.Y)
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
func (p *Point) ScalarMulFixedBase(cs *frontend.ConstraintSystem, x, y interface{}, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	// TODO handle this properly (put the size in curve struct probably)
	var frSize int
	if curve.ID == ecc.BW6_761 {
		frSize = 384
	} else {
		frSize = 256
	}
	b := cs.ToBinary(scalar, frSize)

	res := Point{
		cs.Constant(0),
		cs.Constant(1),
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(cs, &res, curve)
		tmp := Point{}
		tmp.AddFixedPoint(cs, &res, x, y, curve)
		res.X = cs.Select(b[i], tmp.X, res.X)
		res.Y = cs.Select(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// Neg computes the negative of a point in SNARK coordinates
func (p *Point) Neg(cs *frontend.ConstraintSystem, p1 *Point) *Point {
	p.X = cs.Neg(p1.X)
	p.Y = p1.Y
	return p
}
