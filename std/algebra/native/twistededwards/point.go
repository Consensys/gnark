// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/selector"
)

func (p *Point) set(api frontend.API, p1 *Point) *Point {
	p.X = p1.X
	p.Y = p1.Y
	return p
}

func (p *Point) setZero(api frontend.API) *Point {
	p.X = 0
	p.Y = 1
	return p
}

// neg computes the negative of a point in SNARK coordinates
func (p *Point) neg(api frontend.API, p1 *Point) *Point {
	p.X = api.Neg(p1.X)
	p.Y = p1.Y
	return p
}

func (p *Point) Select(api frontend.API, bit frontend.Variable, p1, p2 *Point) *Point {
	p.X = api.Select(bit, p1.X, p2.X)
	p.Y = api.Select(bit, p1.Y, p2.Y)
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
func (p *Point) scalarMulGeneric(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams) *Point {
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

// scalarMulGLVAndFakeGLVLog computes the scalar multiplication of a point on a twisted
// Edwards curve following https://hackmd.io/@yelhousni/Hy-aWld50
//
// [s]p1 == q is equivalent to [u1]p1 + [u2]φ(p1) + [v1]q + [v2]φ(q) = (0,1)
// with u1, u2, v1, v2 < c*sqrt(sqrt(Order)) and u1+λ*u2 + scalar * (v1+λ*v2) == 0 mod Order.
//
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scalar: scalar as a SNARK constraint
// Standard left to right double and add
// It uses logderiv lookup argument for the 16-to-1 lookup table.
func (p *Point) scalarMulGLVAndFakeGLVLog(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo *EndoParams) *Point {
	// the hints allow to decompose the scalar s into u1, u2, v1 and v2 such that
	// u1+λ*u2 + scalar * (v1+λ*v2) == 0 mod Order.
	s, err := api.NewHint(halfGCDZZ2, 4, scalar, endo.Lambda)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	u1, u2, v1, v2 := s[0], s[1], s[2], s[3]

	// check the decomposition using non-native arithmetic
	checkHalfGCDZZ2(api, scalar, endo.Lambda)

	// ZZ2 integers real and imaginary parts can be negative. So we
	// return the absolute value in the hint and negate the corresponding
	// points here when needed.
	signs, err := api.NewHint(halfGCDZZ2Signs, 4, scalar, endo.Lambda)
	if err != nil {
		panic(fmt.Sprintf("halfGCDSigns hint: %v", err))
	}
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// |u1, u2, v1, v2|∞ ≤ 256 · √√2 · √√r
	n := curve.Order.BitLen()/4 + 9
	b1 := api.ToBinary(u1, n)
	b2 := api.ToBinary(u2, n)
	b3 := api.ToBinary(v1, n)
	b4 := api.ToBinary(v2, n)

	q, err := api.NewHint(scalarMulHint, 2, p1.X, p1.Y, scalar, curve.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	// [s]P = Q is equivalent to:
	// [u1]P + [u2]φ(P) + [v1]Q + [v2]φ(Q) = (0,1)
	//
	// Pre-compute:
	// 		T0 = (0,1)
	// 		T1 = P1
	// 		T2 = Q
	// 		T3 = φ(P1)
	// 		T4 = φ(Q)
	// 		T5 = P1 + Q
	// 		T6 = P1 + φ(P1)
	// 		T7 = P1 + φ(Q)
	// 		T8 = Q + φ(P1)
	// 		T9 = Q + φ(Q)
	// 		T10 = φ(P1) + φ(Q)
	// 		T11 = P1 + Q + φ(P1)
	// 		T12 = P1 + Q + φ(Q)
	// 		T13 = P1 + φ(P1) + φ(Q)
	// 		T14 = Q + φ(P1) + φ(Q)
	// 		T15 = P1 + Q + φ(P1) + φ(Q)

	var t [16]Point
	var temp Point
	t[0].setZero(api)
	t[1].Select(api, isNegu1, temp.neg(api, p1), p1)
	t[2] = Point{X: q[0], Y: q[1]}
	t[2].Select(api, isNegv1, temp.neg(api, &t[2]), &t[2])
	t[3].phi(api, p1, curve, endo)
	t[3].Select(api, isNegu2, temp.neg(api, &t[3]), &t[3])
	t[4].phi(api, &Point{X: q[0], Y: q[1]}, curve, endo)
	t[4].Select(api, isNegv2, temp.neg(api, &t[4]), &t[4])
	t[5].add(api, &t[1], &t[2], curve)
	t[6].add(api, &t[1], &t[3], curve)
	t[7].add(api, &t[1], &t[4], curve)
	t[8].add(api, &t[2], &t[3], curve)
	t[9].add(api, &t[2], &t[4], curve)
	t[10].add(api, &t[3], &t[4], curve)
	t[11].add(api, &t[5], &t[3], curve)
	t[12].add(api, &t[5], &t[4], curve)
	t[13].add(api, &t[6], &t[4], curve)
	t[14].add(api, &t[8], &t[4], curve)
	t[15].add(api, &t[7], &t[8], curve)

	flag := api.Add(
		b1[n-1],
		api.Mul(b2[n-1], 2),
		api.Mul(b3[n-1], 4),
		api.Mul(b4[n-1], 8),
	)

	res := Point{
		X: selector.Mux(api, flag,
			t[0].X, t[1].X, t[3].X, t[6].X, t[2].X, t[5].X, t[8].X, t[11].X,
			t[4].X, t[7].X, t[10].X, t[13].X, t[9].X, t[12].X, t[14].X, t[15].X,
		),
		Y: selector.Mux(api, flag,
			t[0].Y, t[1].Y, t[3].Y, t[6].Y, t[2].Y, t[5].Y, t[8].Y, t[11].Y,
			t[4].Y, t[7].Y, t[10].Y, t[13].Y, t[9].Y, t[12].Y, t[14].Y, t[15].Y,
		),
	}
	tblX := logderivlookup.New(api)
	tblX.Insert(t[0].X)
	tblX.Insert(t[1].X)
	tblX.Insert(t[3].X)
	tblX.Insert(t[6].X)
	tblX.Insert(t[2].X)
	tblX.Insert(t[5].X)
	tblX.Insert(t[8].X)
	tblX.Insert(t[11].X)
	tblX.Insert(t[4].X)
	tblX.Insert(t[7].X)
	tblX.Insert(t[10].X)
	tblX.Insert(t[13].X)
	tblX.Insert(t[9].X)
	tblX.Insert(t[12].X)
	tblX.Insert(t[14].X)
	tblX.Insert(t[15].X)

	tblY := logderivlookup.New(api)
	tblY.Insert(t[0].Y)
	tblY.Insert(t[1].Y)
	tblY.Insert(t[3].Y)
	tblY.Insert(t[6].Y)
	tblY.Insert(t[2].Y)
	tblY.Insert(t[5].Y)
	tblY.Insert(t[8].Y)
	tblY.Insert(t[11].Y)
	tblY.Insert(t[4].Y)
	tblY.Insert(t[7].Y)
	tblY.Insert(t[10].Y)
	tblY.Insert(t[13].Y)
	tblY.Insert(t[9].Y)
	tblY.Insert(t[12].Y)
	tblY.Insert(t[14].Y)
	tblY.Insert(t[15].Y)

	for i := n - 2; i >= 0; i-- {
		flag = api.Add(
			b1[i],
			api.Mul(b2[i], 2),
			api.Mul(b3[i], 4),
			api.Mul(b4[i], 8),
		)

		res.double(api, &res, curve)
		temp = Point{
			X: tblX.Lookup(flag)[0],
			Y: tblY.Lookup(flag)[0],
			// X: selector.Mux(api, flag,
			// 	t[0].X, t[1].X, t[3].X, t[6].X, t[2].X, t[5].X, t[8].X, t[11].X,
			// 	t[4].X, t[7].X, t[10].X, t[13].X, t[9].X, t[12].X, t[14].X, t[15].X,
			// ),
			// Y: selector.Mux(api, flag,
			// 	t[0].Y, t[1].Y, t[3].Y, t[6].Y, t[2].Y, t[5].Y, t[8].Y, t[11].Y,
			// 	t[4].Y, t[7].Y, t[10].Y, t[13].Y, t[9].Y, t[12].Y, t[14].Y, t[15].Y,
			// ),
		}
		res.add(api, &res, &temp, curve)
	}

	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	p.X = q[0]
	p.Y = q[1]

	return p
}

// scalarMulGLVAndFakeGLV computes the scalar multiplication of a point on a twisted
// Edwards curve following https://hackmd.io/@yelhousni/Hy-aWld50
//
// [s]p1 == q is equivalent to [u1]p1 + [u2]φ(p1) + [v1]q + [v2]φ(q) = (0,1)
// with u1, u2, v1, v2 < c*sqrt(sqrt(Order)) and u1+λ*u2 + scalar * (v1+λ*v2) == 0 mod Order.
//
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scalar: scalar as a SNARK constraint
// Standard left to right double and add
// It uses a multiplexer for the 16-to-1 lookup table.
func (p *Point) scalarMulGLVAndFakeGLV(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo *EndoParams) *Point {
	// the hints allow to decompose the scalar s into u1, u2, v1 and v2 such that
	// u1+λ*u2 + scalar * (v1+λ*v2) == 0 mod Order.
	s, err := api.NewHint(halfGCDZZ2, 4, scalar, endo.Lambda)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	u1, u2, v1, v2 := s[0], s[1], s[2], s[3]

	// check the decomposition using non-native arithmetic
	checkHalfGCDZZ2(api, scalar, endo.Lambda)

	// ZZ2 integers real and imaginary parts can be negative. So we
	// return the absolute value in the hint and negate the corresponding
	// points here when needed.
	signs, err := api.NewHint(halfGCDZZ2Signs, 4, scalar, endo.Lambda)
	if err != nil {
		panic(fmt.Sprintf("halfGCDSigns hint: %v", err))
	}
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// |u1, u2, v1, v2|∞ ≤ 256 · √√2 · √√r
	n := curve.Order.BitLen()/4 + 9
	b1 := api.ToBinary(u1, n)
	b2 := api.ToBinary(u2, n)
	b3 := api.ToBinary(v1, n)
	b4 := api.ToBinary(v2, n)

	q, err := api.NewHint(scalarMulHint, 2, p1.X, p1.Y, scalar, curve.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	// [s]P = Q is equivalent to:
	// [u1]P + [u2]φ(P) + [v1]Q + [v2]φ(Q) = (0,1)
	//
	// Pre-compute:
	// 		T0 = (0,1)
	// 		T1 = P1
	// 		T2 = Q
	// 		T3 = φ(P1)
	// 		T4 = φ(Q)
	// 		T5 = P1 + Q
	// 		T6 = P1 + φ(P1)
	// 		T7 = P1 + φ(Q)
	// 		T8 = Q + φ(P1)
	// 		T9 = Q + φ(Q)
	// 		T10 = φ(P1) + φ(Q)
	// 		T11 = P1 + Q + φ(P1)
	// 		T12 = P1 + Q + φ(Q)
	// 		T13 = P1 + φ(P1) + φ(Q)
	// 		T14 = Q + φ(P1) + φ(Q)
	// 		T15 = P1 + Q + φ(P1) + φ(Q)

	var t [16]Point
	var temp Point
	t[0].setZero(api)
	t[1].Select(api, isNegu1, temp.neg(api, p1), p1)
	t[2] = Point{X: q[0], Y: q[1]}
	t[2].Select(api, isNegv1, temp.neg(api, &t[2]), &t[2])
	t[3].phi(api, p1, curve, endo)
	t[3].Select(api, isNegu2, temp.neg(api, &t[3]), &t[3])
	t[4].phi(api, &Point{X: q[0], Y: q[1]}, curve, endo)
	t[4].Select(api, isNegv2, temp.neg(api, &t[4]), &t[4])
	t[5].add(api, &t[1], &t[2], curve)
	t[6].add(api, &t[1], &t[3], curve)
	t[7].add(api, &t[1], &t[4], curve)
	t[8].add(api, &t[2], &t[3], curve)
	t[9].add(api, &t[2], &t[4], curve)
	t[10].add(api, &t[3], &t[4], curve)
	t[11].add(api, &t[5], &t[3], curve)
	t[12].add(api, &t[5], &t[4], curve)
	t[13].add(api, &t[6], &t[4], curve)
	t[14].add(api, &t[8], &t[4], curve)
	t[15].add(api, &t[7], &t[8], curve)

	flag := api.Add(
		b1[n-1],
		api.Mul(b2[n-1], 2),
		api.Mul(b3[n-1], 4),
		api.Mul(b4[n-1], 8),
	)

	res := Point{
		X: selector.Mux(api, flag,
			t[0].X, t[1].X, t[3].X, t[6].X, t[2].X, t[5].X, t[8].X, t[11].X,
			t[4].X, t[7].X, t[10].X, t[13].X, t[9].X, t[12].X, t[14].X, t[15].X,
		),
		Y: selector.Mux(api, flag,
			t[0].Y, t[1].Y, t[3].Y, t[6].Y, t[2].Y, t[5].Y, t[8].Y, t[11].Y,
			t[4].Y, t[7].Y, t[10].Y, t[13].Y, t[9].Y, t[12].Y, t[14].Y, t[15].Y,
		),
	}

	for i := n - 2; i >= 0; i-- {
		flag = api.Add(
			b1[i],
			api.Mul(b2[i], 2),
			api.Mul(b3[i], 4),
			api.Mul(b4[i], 8),
		)

		res.double(api, &res, curve)
		temp = Point{
			X: selector.Mux(api, flag,
				t[0].X, t[1].X, t[3].X, t[6].X, t[2].X, t[5].X, t[8].X, t[11].X,
				t[4].X, t[7].X, t[10].X, t[13].X, t[9].X, t[12].X, t[14].X, t[15].X,
			),
			Y: selector.Mux(api, flag,
				t[0].Y, t[1].Y, t[3].Y, t[6].Y, t[2].Y, t[5].Y, t[8].Y, t[11].Y,
				t[4].Y, t[7].Y, t[10].Y, t[13].Y, t[9].Y, t[12].Y, t[14].Y, t[15].Y,
			),
		}
		res.add(api, &res, &temp, curve)
	}

	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	p.X = q[0]
	p.Y = q[1]

	return p
}
