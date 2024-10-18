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

import "github.com/consensys/gnark/frontend"

// neg computes the negative of a point in SNARK coordinates
func (p *Point) neg(api frontend.API, p1 *Point) *Point {
	p.X = api.Neg(p1.X)
	p.Y = p1.Y
	return p
}

// assertIsOnCurve checks if a point is on the reduced twisted Edwards curve
// a*x² + y² = 1 + d*x²*y².
func (p *Point) assertIsOnCurve(api frontend.API, curve *CurveParams) {

	xx := api.Mul(p.X, p.X)
	yy := api.Mul(p.Y, p.Y)
	axx := api.Mul(xx, curve.A)
	lhs := api.Add(axx, yy)

	dxx := api.Mul(xx, curve.D)
	dxxyy := api.Mul(dxx, yy)
	rhs := api.Add(dxxyy, 1)

	api.AssertIsEqual(lhs, rhs)

}

// add Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) add(api frontend.API, p1, p2 *Point, curve *CurveParams) *Point {

	// u = (x1 + y1) * (x2 + y2)
	u1 := api.Mul(p1.X, curve.A)
	u1 = api.Sub(p1.Y, u1)
	u2 := api.Add(p2.X, p2.Y)
	u := api.Mul(u1, u2)

	// v0 = x1 * y2
	v0 := api.Mul(p2.Y, p1.X)

	// v1 = x2 * y1
	v1 := api.Mul(p2.X, p1.Y)

	// v2 = d * v0 * v1
	v2 := api.Mul(curve.D, v0, v1)

	// x = (v0 + v1) / (1 + v2)
	p.X = api.Add(v0, v1)
	p.X = api.DivUnchecked(p.X, api.Add(1, v2))

	// y = (u + a * v0 - v1) / (1 - v2)
	p.Y = api.Mul(curve.A, v0)
	p.Y = api.Sub(p.Y, v1)
	p.Y = api.Add(p.Y, u)
	p.Y = api.DivUnchecked(p.Y, api.Sub(1, v2))

	return p
}

// double doubles a points in SNARK coordinates
func (p *Point) double(api frontend.API, p1 *Point, curve *CurveParams) *Point {

	u := api.Mul(p1.X, p1.Y)
	v := api.Mul(p1.X, p1.X)
	w := api.Mul(p1.Y, p1.Y)

	n1 := api.Mul(2, u)
	av := api.Mul(v, curve.A)
	n2 := api.Sub(w, av)
	d1 := api.Add(w, av)
	d2 := api.Sub(2, d1)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// scalarMulGeneric computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) scalarMulGeneric(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo ...*EndoParams) *Point {
	// first unpack the scalar
	b := api.ToBinary(scalar)

	res := Point{}
	tmp := Point{}
	A := Point{}
	B := Point{}

	A.double(api, p1, curve)
	B.add(api, &A, p1, curve)

	n := len(b) - 1
	res.X = api.Lookup2(b[n], b[n-1], 0, A.X, p1.X, B.X)
	res.Y = api.Lookup2(b[n], b[n-1], 1, A.Y, p1.Y, B.Y)

	for i := n - 2; i >= 1; i -= 2 {
		res.double(api, &res, curve).
			double(api, &res, curve)
		tmp.X = api.Lookup2(b[i], b[i-1], 0, A.X, p1.X, B.X)
		tmp.Y = api.Lookup2(b[i], b[i-1], 1, A.Y, p1.Y, B.Y)
		res.add(api, &res, &tmp, curve)
	}

	if n%2 == 0 {
		res.double(api, &res, curve)
		tmp.add(api, &res, p1, curve)
		res.X = api.Select(b[0], tmp.X, res.X)
		res.Y = api.Select(b[0], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// scalarMul computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) scalarMul(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo ...*EndoParams) *Point {
	return p.scalarMulFakeGLV(api, p1, scalar, curve)
}

// doubleBaseScalarMul computes s1*P1+s2*P2
// where P1 and P2 are points on a twisted Edwards curve
// and s1, s2 scalars.
func (p *Point) doubleBaseScalarMul(api frontend.API, p1, p2 *Point, s1, s2 frontend.Variable, curve *CurveParams) *Point {

	// first unpack the scalars
	b1 := api.ToBinary(s1)
	b2 := api.ToBinary(s2)

	res := Point{}
	tmp := Point{}
	sum := Point{}
	sum.add(api, p1, p2, curve)

	n := len(b1)
	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, p1.X, p2.X, sum.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, p1.Y, p2.Y, sum.Y)

	for i := n - 2; i >= 0; i-- {
		res.double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, p1.X, p2.X, sum.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, p1.Y, p2.Y, sum.Y)
		res.add(api, &res, &tmp, curve)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// GLV

// phi endomorphism √-2 ∈ 𝒪₋₈
// (x,y) → λ × (x,y) s.t. λ² = -2 mod Order
func (p *Point) phi(api frontend.API, p1 *Point, curve *CurveParams, endo *EndoParams) *Point {

	xy := api.Mul(p1.X, p1.Y)
	yy := api.Mul(p1.Y, p1.Y)
	f := api.Sub(1, yy)
	f = api.Mul(f, endo.Endo[1])
	g := api.Add(yy, endo.Endo[0])
	g = api.Mul(g, endo.Endo[0])
	h := api.Sub(yy, endo.Endo[0])

	p.X = api.DivUnchecked(f, xy)
	p.Y = api.DivUnchecked(g, h)

	return p
}

// scalarMulGLV computes the scalar multiplication of a point on a twisted
// Edwards curve à la GLV.
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) scalarMulGLV(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo *EndoParams) *Point {
	// the hints allow to decompose the scalar s into s1 and s2 such that
	// s1 + λ * s2 == s mod Order,
	// with λ s.t. λ² = -2 mod Order.
	sd, err := api.NewHint(decomposeScalar, 3, scalar)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	s1, s2 := sd[0], sd[1]

	// -s1 + λ * s2 == s + k*Order
	api.AssertIsEqual(api.Sub(api.Mul(s2, endo.Lambda), s1), api.Add(scalar, api.Mul(curve.Order, sd[2])))

	// Normally s1 and s2 are of the max size sqrt(Order) = 128
	// But in a circuit, we force s1 to be negative by rounding always above.
	// This changes the size bounds to 2*sqrt(Order) = 129.
	n := 129

	b1 := api.ToBinary(s1, n)
	b2 := api.ToBinary(s2, n)

	var res, _p1, p2, p3, tmp Point
	_p1.neg(api, p1)
	p2.phi(api, p1, curve, endo)
	p3.add(api, &_p1, &p2, curve)

	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, _p1.X, p2.X, p3.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, _p1.Y, p2.Y, p3.Y)

	for i := n - 2; i >= 0; i-- {
		res.double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, _p1.X, p2.X, p3.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, _p1.Y, p2.Y, p3.Y)
		res.add(api, &res, &tmp, curve)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// scalarMulFakeGLV computes the scalar multiplication of a point on a twisted
// Edwards curve following https://hackmd.io/@yelhousni/Hy-aWld50
//
// [s]p1 == q is equivalent to [s2]([s]p1 - q) = (0,1) which is [s1]p1 + [s2]q = (0,1)
// with s1, s2 < sqrt(Order) and s1 + s2 * s = 0 mod Order.
//
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) scalarMulFakeGLV(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams) *Point {
	// the hints allow to decompose the scalar s into s1 and s2 such that
	// s1 + s * s2 == 0 mod Order,
	s, err := api.NewHint(halfGCD, 4, scalar, curve.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2, bit, k := s[0], s[1], s[2], s[3]

	// check that s1 + s2 * s == k*Order
	_s2 := api.Mul(s2, scalar)
	_k := api.Mul(k, curve.Order)
	lhs := api.Select(bit, s1, api.Add(s1, _s2))
	rhs := api.Select(bit, api.Add(_k, _s2), _k)
	api.AssertIsEqual(lhs, rhs)

	n := (curve.Order.BitLen() + 1) / 2
	b1 := api.ToBinary(s1, n)
	b2 := api.ToBinary(s2, n)

	var res, p2, p3, tmp Point
	q, err := api.NewHint(scalarMulHint, 2, p1.X, p1.Y, scalar, curve.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	p2.X = api.Select(bit, api.Neg(q[0]), q[0])
	p2.Y = q[1]

	p3.add(api, p1, &p2, curve)

	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, p1.X, p2.X, p3.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, p1.Y, p2.Y, p3.Y)

	for i := n - 2; i >= 0; i-- {
		res.double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, p1.X, p2.X, p3.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, p1.Y, p2.Y, p3.Y)
		res.add(api, &res, &tmp, curve)
	}

	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	p.X = q[0]
	p.Y = q[1]

	return p
}
