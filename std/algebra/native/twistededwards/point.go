// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

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
	// Handle edge case: if scalar is zero, return identity point (0, 1)
	scalarIsZero := api.IsZero(scalar)

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

	// Return identity (0, 1) when scalar is zero, otherwise return computed result
	p.X = api.Select(scalarIsZero, 0, res.X)
	p.Y = api.Select(scalarIsZero, 1, res.Y)

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
	// Handle edge case: if scalar is zero, return identity point (0, 1)
	scalarIsZero := api.IsZero(scalar)

	// Use a dummy non-zero scalar (1) when the actual scalar is zero to avoid
	// division by zero in the hint. The result will be selected away anyway.
	scalarForHint := api.Select(scalarIsZero, 1, scalar)

	// the hints allow to decompose the scalar s into s1 and s2 such that
	// s1 + s * s2 == 0 mod Order,
	s, err := api.NewHint(rationalReconstruct, 4, scalarForHint, curve.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2, bit, k := s[0], s[1], s[2], s[3]

	// check that s1 + s2 * s == k*Order (only when scalar is non-zero)
	_s2 := api.Mul(s2, scalarForHint)
	_k := api.Mul(k, curve.Order)
	lhs := api.Select(bit, s1, api.Add(s1, _s2))
	rhs := api.Select(bit, api.Add(_k, _s2), _k)
	// When scalar is zero, we use dummy values, so skip this check
	lhsCheck := api.Select(scalarIsZero, 0, lhs)
	rhsCheck := api.Select(scalarIsZero, 0, rhs)
	api.AssertIsEqual(lhsCheck, rhsCheck)

	n := (curve.Order.BitLen() + 1) / 2
	b1 := api.ToBinary(s1, n)
	b2 := api.ToBinary(s2, n)

	var res, p2, p3, tmp Point
	q, err := api.NewHint(scalarMulHint, 2, p1.X, p1.Y, scalarForHint, curve.Order)
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

	// When scalar is non-zero, verify the computation
	// When scalar is zero, skip verification (we return identity anyway)
	resXCheck := api.Select(scalarIsZero, 0, res.X)
	resYCheck := api.Select(scalarIsZero, 1, res.Y)
	api.AssertIsEqual(resXCheck, 0)
	api.AssertIsEqual(resYCheck, 1)

	// Return identity (0, 1) when scalar is zero, otherwise return computed result
	p.X = api.Select(scalarIsZero, 0, q[0])
	p.Y = api.Select(scalarIsZero, 1, q[1])

	return p
}

// doubleBaseScalarMul3MSMLogUp computes s1*P1+s2*P2 using MultiRationalReconstruct (true 3-MSM).
// This decomposes both scalars with a shared denominator in Z, giving ~r^(2/3)-bit scalars.
// Verifies: [x1]P + [x2]Q = [z]R
// where R = [s1]P + [s2]Q (hinted).
// Uses LogDerivLookup for the 4-point multi-scalar multiplication (16-entry table).
func (p *Point) doubleBaseScalarMul3MSMLogUp(api frontend.API, p1, p2 *Point, s1, s2 frontend.Variable, curve *CurveParams) *Point {
	// Get hinted results Q1 = [s1]P1 and Q2 = [s2]P2
	q, err := api.NewHint(doubleBaseScalarMulHint, 4, p1.X, p1.Y, s1, p2.X, p2.Y, s2, curve.Order)
	if err != nil {
		panic(err)
	}
	var Q1, Q2 Point
	Q1.X, Q1.Y = q[0], q[1]
	Q2.X, Q2.Y = q[2], q[3]

	// Decompose s1 into (u1, v1) such that u1 + s1*v1 ≡ 0 (mod Order)
	h1, err := api.NewHint(rationalReconstruct, 4, s1, curve.Order)
	if err != nil {
		panic(err)
	}
	u1, v1, bit1, k1 := h1[0], h1[1], h1[2], h1[3]

	// Verify: u1 + s1*v1 == k1*Order (with sign handling)
	_v1s1 := api.Mul(v1, s1)
	_k1r := api.Mul(k1, curve.Order)
	lhs1 := api.Select(bit1, u1, api.Add(u1, _v1s1))
	rhs1 := api.Select(bit1, api.Add(_k1r, _v1s1), _k1r)
	api.AssertIsEqual(lhs1, rhs1)

	// Decompose s2 into (u2, v2) such that u2 + s2*v2 ≡ 0 (mod Order)
	h2, err := api.NewHint(rationalReconstruct, 4, s2, curve.Order)
	if err != nil {
		panic(err)
	}
	u2, v2, bit2, k2 := h2[0], h2[1], h2[2], h2[3]

	// Verify: u2 + s2*v2 == k2*Order (with sign handling)
	_v2s2 := api.Mul(v2, s2)
	_k2r := api.Mul(k2, curve.Order)
	lhs2 := api.Select(bit2, u2, api.Add(u2, _v2s2))
	rhs2 := api.Select(bit2, api.Add(_k2r, _v2s2), _k2r)
	api.AssertIsEqual(lhs2, rhs2)

	// Apply sign to Q1 and Q2 based on decomposition
	var _Q1, _Q2 Point
	_Q1.X = api.Select(bit1, api.Neg(Q1.X), Q1.X)
	_Q1.Y = Q1.Y
	_Q2.X = api.Select(bit2, api.Neg(Q2.X), Q2.X)
	_Q2.Y = Q2.Y

	// Build the 16-entry table for 4-MSM: P1, _Q1, P2, _Q2
	var table [16]Point

	// Precompute pair sums
	var P1Q1, P2Q2, P1P2, P1Q2, Q1P2, Q1Q2 Point
	P1Q1.add(api, p1, &_Q1, curve)
	P2Q2.add(api, p2, &_Q2, curve)
	P1P2.add(api, p1, p2, curve)
	P1Q2.add(api, p1, &_Q2, curve)
	Q1P2.add(api, &_Q1, p2, curve)
	Q1Q2.add(api, &_Q1, &_Q2, curve)

	// Precompute triple sums
	var P1Q1P2, P1Q1Q2, P1P2Q2, Q1P2Q2 Point
	P1Q1P2.add(api, &P1Q1, p2, curve)
	P1Q1Q2.add(api, &P1Q1, &_Q2, curve)
	P1P2Q2.add(api, &P1P2, &_Q2, curve)
	Q1P2Q2.add(api, &Q1P2, &_Q2, curve)

	// Precompute quad sum
	var P1Q1P2Q2 Point
	P1Q1P2Q2.add(api, &P1Q1P2, &_Q2, curve)

	// Build table: index i = b0 + 2*b1 + 4*b2 + 8*b3
	table[0] = Point{X: 0, Y: 1}
	table[1] = *p1
	table[2] = _Q1
	table[3] = P1Q1
	table[4] = *p2
	table[5] = P1P2
	table[6] = Q1P2
	table[7] = P1Q1P2
	table[8] = _Q2
	table[9] = P1Q2
	table[10] = Q1Q2
	table[11] = P1Q1Q2
	table[12] = P2Q2
	table[13] = P1P2Q2
	table[14] = Q1P2Q2
	table[15] = P1Q1P2Q2

	// Create LogDerivLookup tables
	tableX := logderivlookup.New(api)
	tableY := logderivlookup.New(api)
	for i := 0; i < 16; i++ {
		tableX.Insert(table[i].X)
		tableY.Insert(table[i].Y)
	}

	n := (curve.Order.BitLen() + 1) / 2
	b1 := api.ToBinary(u1, n)
	b2 := api.ToBinary(v1, n)
	b3 := api.ToBinary(u2, n)
	b4 := api.ToBinary(v2, n)

	// Compute indices for lookups
	indices := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		// index = b1[i] + 2*b2[i] + 4*b3[i] + 8*b4[i]
		indices[i] = api.Add(
			b1[i],
			api.Mul(b2[i], 2),
			api.Mul(b3[i], 4),
			api.Mul(b4[i], 8),
		)
	}

	// Batch lookup
	resX := tableX.Lookup(indices...)
	resY := tableY.Lookup(indices...)

	// Initialize accumulator with first entry
	var res Point
	res.X = resX[n-1]
	res.Y = resY[n-1]

	for i := n - 2; i >= 0; i-- {
		res.double(api, &res, curve)
		var tmp Point
		tmp.X = resX[i]
		tmp.Y = resY[i]
		res.add(api, &res, &tmp, curve)
	}

	// Verify accumulator equals identity (0, 1)
	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	// Return Q1 + Q2
	p.add(api, &Q1, &Q2, curve)

	return p
}

// doubleBaseScalarMul6MSMLogUp computes s1*P1+s2*P2 using MultiRationalReconstructExt (true 6-MSM).
// This decomposes both scalars with a shared denominator in Z[λ], giving ~r^(1/3)-bit scalars.
// Verifies: [x1]P + [y1]φ(P) + [x2]Q + [y2]φ(Q) = [z]R + [t]φ(R)
// where R = [s1]P + [s2]Q (hinted).
// Only works for curves with efficient endomorphism (e.g., Bandersnatch).
// Uses LogDerivLookup for the 64-entry table (6 points).
func (p *Point) doubleBaseScalarMul6MSMLogUp(api frontend.API, p1, p2 *Point, s1, s2 frontend.Variable, curve *CurveParams, endo *EndoParams) *Point {
	// Get hinted result R = [s1]P + [s2]Q
	qHint, err := api.NewHint(doubleBaseScalarMulHint, 4, p1.X, p1.Y, s1, p2.X, p2.Y, s2, curve.Order)
	if err != nil {
		panic(err)
	}
	var R Point
	// We need Q1 + Q2 = R
	var Q1, Q2 Point
	Q1.X, Q1.Y = qHint[0], qHint[1]
	Q2.X, Q2.Y = qHint[2], qHint[3]
	R.add(api, &Q1, &Q2, curve)

	// Decompose (s1, s2) using MultiRationalReconstructExt
	// Returns |x1|, |y1|, |x2|, |y2|, |z|, |t|, signX1, signY1, signX2, signY2, signZ, signT
	h, err := api.NewHint(multiRationalReconstructExtHint, 12, s1, s2, curve.Order, endo.Lambda)
	if err != nil {
		panic(err)
	}
	absX1, absY1, absX2, absY2, absZ, absT := h[0], h[1], h[2], h[3], h[4], h[5]
	signX1, signY1, signX2, signY2, signZ, signT := h[6], h[7], h[8], h[9], h[10], h[11]

	// Compute φ(P1), φ(P2), φ(R)
	var phiP1, phiP2, phiR Point
	phiP1.phi(api, p1, curve, endo)
	phiP2.phi(api, p2, curve, endo)
	phiR.phi(api, &R, curve, endo)

	// Apply signs to create signed points for the 6-MSM
	// The verification is: [x1]P + [y1]φ(P) + [x2]Q + [y2]φ(Q) - [z]R - [t]φ(R) = O
	// With signs: we negate the point when the sign is 1
	var sP1, sPhiP1, sP2, sPhiP2, sR, sPhiR Point

	// For P1: if signX1 == 1, use -P1, else use P1
	sP1.X = api.Select(signX1, api.Neg(p1.X), p1.X)
	sP1.Y = p1.Y

	// For φ(P1): if signY1 == 1, use -φ(P1), else use φ(P1)
	sPhiP1.X = api.Select(signY1, api.Neg(phiP1.X), phiP1.X)
	sPhiP1.Y = phiP1.Y

	// For P2: if signX2 == 1, use -P2, else use P2
	sP2.X = api.Select(signX2, api.Neg(p2.X), p2.X)
	sP2.Y = p2.Y

	// For φ(P2): if signY2 == 1, use -φ(P2), else use φ(P2)
	sPhiP2.X = api.Select(signY2, api.Neg(phiP2.X), phiP2.X)
	sPhiP2.Y = phiP2.Y

	// For R: we subtract [z]R, so if signZ == 0 (z positive), use -R; if signZ == 1 (z negative), use R
	sR.X = api.Select(signZ, R.X, api.Neg(R.X))
	sR.Y = R.Y

	// For φ(R): similarly for t
	sPhiR.X = api.Select(signT, phiR.X, api.Neg(phiR.X))
	sPhiR.Y = phiR.Y

	// Build 64-entry table for 6-MSM
	// Index = b0 + 2*b1 + 4*b2 + 8*b3 + 16*b4 + 32*b5
	// Points: sP1, sPhiP1, sP2, sPhiP2, sR, sPhiR
	var table [64]Point

	// Precompute all 64 combinations
	// table[i] = (i&1)*sP1 + ((i>>1)&1)*sPhiP1 + ((i>>2)&1)*sP2 + ((i>>3)&1)*sPhiP2 + ((i>>4)&1)*sR + ((i>>5)&1)*sPhiR

	// Start with identity
	table[0] = Point{X: 0, Y: 1}

	// Single points
	table[1] = sP1
	table[2] = sPhiP1
	table[4] = sP2
	table[8] = sPhiP2
	table[16] = sR
	table[32] = sPhiR

	// 2-combinations
	table[3].add(api, &sP1, &sPhiP1, curve)
	table[5].add(api, &sP1, &sP2, curve)
	table[6].add(api, &sPhiP1, &sP2, curve)
	table[9].add(api, &sP1, &sPhiP2, curve)
	table[10].add(api, &sPhiP1, &sPhiP2, curve)
	table[12].add(api, &sP2, &sPhiP2, curve)
	table[17].add(api, &sP1, &sR, curve)
	table[18].add(api, &sPhiP1, &sR, curve)
	table[20].add(api, &sP2, &sR, curve)
	table[24].add(api, &sPhiP2, &sR, curve)
	table[33].add(api, &sP1, &sPhiR, curve)
	table[34].add(api, &sPhiP1, &sPhiR, curve)
	table[36].add(api, &sP2, &sPhiR, curve)
	table[40].add(api, &sPhiP2, &sPhiR, curve)
	table[48].add(api, &sR, &sPhiR, curve)

	// 3-combinations (build from 2-combinations)
	table[7].add(api, &table[3], &sP2, curve)     // sP1 + sPhiP1 + sP2
	table[11].add(api, &table[3], &sPhiP2, curve) // sP1 + sPhiP1 + sPhiP2
	table[13].add(api, &table[5], &sPhiP2, curve) // sP1 + sP2 + sPhiP2
	table[14].add(api, &table[6], &sPhiP2, curve) // sPhiP1 + sP2 + sPhiP2
	table[19].add(api, &table[3], &sR, curve)     // sP1 + sPhiP1 + sR
	table[21].add(api, &table[5], &sR, curve)     // sP1 + sP2 + sR
	table[22].add(api, &table[6], &sR, curve)     // sPhiP1 + sP2 + sR
	table[25].add(api, &table[9], &sR, curve)     // sP1 + sPhiP2 + sR
	table[26].add(api, &table[10], &sR, curve)    // sPhiP1 + sPhiP2 + sR
	table[28].add(api, &table[12], &sR, curve)    // sP2 + sPhiP2 + sR
	table[35].add(api, &table[3], &sPhiR, curve)  // sP1 + sPhiP1 + sPhiR
	table[37].add(api, &table[5], &sPhiR, curve)  // sP1 + sP2 + sPhiR
	table[38].add(api, &table[6], &sPhiR, curve)  // sPhiP1 + sP2 + sPhiR
	table[41].add(api, &table[9], &sPhiR, curve)  // sP1 + sPhiP2 + sPhiR
	table[42].add(api, &table[10], &sPhiR, curve) // sPhiP1 + sPhiP2 + sPhiR
	table[44].add(api, &table[12], &sPhiR, curve) // sP2 + sPhiP2 + sPhiR
	table[49].add(api, &table[17], &sPhiR, curve) // sP1 + sR + sPhiR
	table[50].add(api, &table[18], &sPhiR, curve) // sPhiP1 + sR + sPhiR
	table[52].add(api, &table[20], &sPhiR, curve) // sP2 + sR + sPhiR
	table[56].add(api, &table[24], &sPhiR, curve) // sPhiP2 + sR + sPhiR

	// 4-combinations
	table[15].add(api, &table[7], &sPhiP2, curve) // sP1 + sPhiP1 + sP2 + sPhiP2
	table[23].add(api, &table[7], &sR, curve)     // sP1 + sPhiP1 + sP2 + sR
	table[27].add(api, &table[11], &sR, curve)    // sP1 + sPhiP1 + sPhiP2 + sR
	table[29].add(api, &table[13], &sR, curve)    // sP1 + sP2 + sPhiP2 + sR
	table[30].add(api, &table[14], &sR, curve)    // sPhiP1 + sP2 + sPhiP2 + sR
	table[39].add(api, &table[7], &sPhiR, curve)  // sP1 + sPhiP1 + sP2 + sPhiR
	table[43].add(api, &table[11], &sPhiR, curve) // sP1 + sPhiP1 + sPhiP2 + sPhiR
	table[45].add(api, &table[13], &sPhiR, curve) // sP1 + sP2 + sPhiP2 + sPhiR
	table[46].add(api, &table[14], &sPhiR, curve) // sPhiP1 + sP2 + sPhiP2 + sPhiR
	table[51].add(api, &table[19], &sPhiR, curve) // sP1 + sPhiP1 + sR + sPhiR
	table[53].add(api, &table[21], &sPhiR, curve) // sP1 + sP2 + sR + sPhiR
	table[54].add(api, &table[22], &sPhiR, curve) // sPhiP1 + sP2 + sR + sPhiR
	table[57].add(api, &table[25], &sPhiR, curve) // sP1 + sPhiP2 + sR + sPhiR
	table[58].add(api, &table[26], &sPhiR, curve) // sPhiP1 + sPhiP2 + sR + sPhiR
	table[60].add(api, &table[28], &sPhiR, curve) // sP2 + sPhiP2 + sR + sPhiR

	// 5-combinations
	table[31].add(api, &table[15], &sR, curve)    // all except sPhiR
	table[47].add(api, &table[15], &sPhiR, curve) // all except sR
	table[55].add(api, &table[23], &sPhiR, curve) // sP1 + sPhiP1 + sP2 + sR + sPhiR
	table[59].add(api, &table[27], &sPhiR, curve) // sP1 + sPhiP1 + sPhiP2 + sR + sPhiR
	table[61].add(api, &table[29], &sPhiR, curve) // sP1 + sP2 + sPhiP2 + sR + sPhiR
	table[62].add(api, &table[30], &sPhiR, curve) // sPhiP1 + sP2 + sPhiP2 + sR + sPhiR

	// 6-combination (all points)
	table[63].add(api, &table[31], &sPhiR, curve)

	// Use LogDerivLookup for the 64-entry table
	tableX := logderivlookup.New(api)
	tableY := logderivlookup.New(api)
	for i := 0; i < 64; i++ {
		tableX.Insert(table[i].X)
		tableY.Insert(table[i].Y)
	}

	// Scalar bit length: ~r^(1/3) ≈ 85 bits for 254-bit order
	n := (curve.Order.BitLen() + 2) / 3

	bX1 := api.ToBinary(absX1, n)
	bY1 := api.ToBinary(absY1, n)
	bX2 := api.ToBinary(absX2, n)
	bY2 := api.ToBinary(absY2, n)
	bZ := api.ToBinary(absZ, n)
	bT := api.ToBinary(absT, n)

	// Compute indices for lookups
	indices := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		indices[i] = api.Add(
			bX1[i],
			api.Mul(bY1[i], 2),
			api.Mul(bX2[i], 4),
			api.Mul(bY2[i], 8),
			api.Mul(bZ[i], 16),
			api.Mul(bT[i], 32),
		)
	}

	// Batch lookup
	lookupX := tableX.Lookup(indices...)
	lookupY := tableY.Lookup(indices...)

	// Initialize accumulator with last entry
	var acc Point
	acc.X = lookupX[n-1]
	acc.Y = lookupY[n-1]

	for i := n - 2; i >= 0; i-- {
		acc.double(api, &acc, curve)
		var tmp Point
		tmp.X = lookupX[i]
		tmp.Y = lookupY[i]
		acc.add(api, &acc, &tmp, curve)
	}

	// Verify accumulator equals identity (0, 1)
	api.AssertIsEqual(acc.X, 0)
	api.AssertIsEqual(acc.Y, 1)

	// Return R (the hinted result)
	p.X = R.X
	p.Y = R.Y

	return p
}
