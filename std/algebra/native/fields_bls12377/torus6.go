// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"github.com/consensys/gnark/frontend"
)

// Torus-based arithmetic for cyclotomic subgroup
// The torus T₆ represents elements of the cyclotomic subgroup of E12 using E6
// For x in cyclotomic subgroup: x = (1 + y·w) / (1 - y·w) where y ∈ E6

// TorusSquare computes the square in torus representation
// Input: y ∈ E6 representing x ∈ T₆
// Output: y' ∈ E6 representing x² ∈ T₆
// Formula: y' = 2y / (1 + y²·v) where v is the cubic non-residue
func TorusSquare(api frontend.API, y E6) E6 {
	// Compute numerator: 2y
	var num E6
	num.Double(api, y)

	// Compute y²
	var ySq E6
	ySq.Square(api, y)

	// Compute denominator: 1 + y²·v
	var denom E6
	denom.MulByNonResidue(api, ySq)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Compute result = num / denom (DivUnchecked uses hint internally)
	var result E6
	result.DivUnchecked(api, num, denom)

	return result
}

// TorusMul computes multiplication in torus representation
// Input: y1, y2 ∈ E6 representing x1, x2 ∈ T₆
// Output: y' ∈ E6 representing x1·x2 ∈ T₆
// Formula: y' = (y1 + y2) / (1 + y1·y2·v)
func TorusMul(api frontend.API, y1, y2 E6) E6 {
	// Compute numerator: y1 + y2
	var num E6
	num.Add(api, y1, y2)

	// Compute y1·y2
	var prod E6
	prod.Mul(api, y1, y2)

	// Compute denominator: 1 + y1·y2·v
	var denom E6
	denom.MulByNonResidue(api, prod)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Compute result = num / denom (DivUnchecked uses hint internally)
	var result E6
	result.DivUnchecked(api, num, denom)

	return result
}

// TorusMulBy01 computes multiplication by sparse element (l0, l1, 0) in torus
// This is used for line multiplication where the line projects to (-c3, -c4, 0)
// Formula: y' = (y + sparse) / (1 + y·sparse·v)
func TorusMulBy01(api frontend.API, y E6, l0, l1 E2) E6 {
	// Sparse element: (l0, l1, 0)
	var sparse E6
	sparse.B0 = l0
	sparse.B1 = l1
	// B2 is zero - must be explicit circuit zero
	sparse.B2.A0 = 0
	sparse.B2.A1 = 0

	// Compute numerator: y + sparse
	var num E6
	num.Add(api, y, sparse)

	// Compute y · sparse using MulBy01
	var prod E6
	prod = y
	prod.MulBy01(api, l0, l1)

	// Compute denominator: 1 + prod·v
	var denom E6
	denom.MulByNonResidue(api, prod)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Compute result = num / denom (DivUnchecked uses hint internally)
	var result E6
	result.DivUnchecked(api, num, denom)

	return result
}

// TorusDecompress converts torus representation back to E12
// Input: y ∈ E6 representing x ∈ T₆
// Output: x ∈ E12 where x = (1 + y·w) / (1 - y·w)
//
// We compute C0 and C1 such that x = C0 + C1·w
// From (1 + y·w) = (C0 + C1·w)(1 - y·w):
//
//	1 = C0 - C1·y·v  =>  C0 = 1 + C1·y·v
//	y = C1 - C0·y    =>  C1 = y + C0·y = y(1 + C0)
//
// Substituting: C1 = y(1 + 1 + C1·y·v) = y(2 + C1·y·v)
// C1 = 2y + C1·y²·v
// C1(1 - y²·v) = 2y
// C1 = 2y / (1 - y²·v)
func TorusDecompress(api frontend.API, y E6) E12 {
	// Compute y²
	var ySq E6
	ySq.Square(api, y)

	// Compute y²·v
	var ySqV E6
	ySqV.MulByNonResidue(api, ySq)

	// Compute denominator: 1 - y²·v
	var one E6
	one.SetOne()
	var denom E6
	denom.Sub(api, one, ySqV)

	// Compute numerator: 2y
	var num E6
	num.Double(api, y)

	// C1 = 2y / (1 - y²·v)
	var c1 E6
	c1.DivUnchecked(api, num, denom)

	// C0 = 1 + C1·y·v
	var c1y E6
	c1y.Mul(api, c1, y)
	var c1yv E6
	c1yv.MulByNonResidue(api, c1y)
	var c0 E6
	c0.Add(api, one, c1yv)

	return E12{C0: c0, C1: c1}
}

// FrobeniusTorus computes the Frobenius endomorphism on torus element
// For y ∈ E6 representing W in cyclotomic subgroup via W = (1+y·w)/(1-y·w):
// Frob(W) = (1 + z·w) / (1 - z·w) where z = FrobeniusTorus(y)
// Formula:
//
//	z.B0 = Conj(y.B0) · frobw
//	z.B1 = Conj(y.B1) · frobvw
//	z.B2 = Conj(y.B2) · frobv2w
func FrobeniusTorus(api frontend.API, y E6) E6 {
	var z E6
	z.B0.Conjugate(api, y.B0).MulByFp(api, z.B0, ext.frobw)
	z.B1.Conjugate(api, y.B1).MulByFp(api, z.B1, ext.frobvw)
	z.B2.Conjugate(api, y.B2).MulByFp(api, z.B2, ext.frobv2w)
	return z
}

// TorusCompress computes compress(x) = C1 / (1 + C0)
// Input: x ∈ E12 in cyclotomic subgroup
// Output: y ∈ E6 such that x = (1 + y·w) / (1 - y·w)
func TorusCompress(api frontend.API, x E12) E6 {
	// y = C1 / (1 + C0)
	var one E6
	one.SetOne()
	var c0PlusOne E6
	c0PlusOne.Add(api, x.C0, one)

	var y E6
	y.DivUnchecked(api, x.C1, c0PlusOne)

	return y
}

// CompressFrobDivideByScaling computes compress(Frob(W) / s) where W = decompress(y)
// Formula: result = 2·z / (1 + s + z²·v·(1 - s))
// where z = FrobeniusTorus(y)
func CompressFrobDivideByScaling(api frontend.API, y E6, s E6) E6 {
	// Compute z = FrobeniusTorus(y)
	z := FrobeniusTorus(api, y)

	// Compute z²
	var zSquare E6
	zSquare.Square(api, z)

	// Compute z²·v (multiply by non-residue)
	var zSquareV E6
	zSquareV.MulByNonResidue(api, zSquare)

	// Compute (1 - s)
	var one E6
	one.SetOne()
	var oneMinusS E6
	oneMinusS.Sub(api, one, s)

	// Compute z²·v·(1 - s)
	var term E6
	term.Mul(api, zSquareV, oneMinusS)

	// Compute denominator = 1 + s + z²·v·(1 - s)
	var denom E6
	denom.Add(api, one, s)
	denom.Add(api, denom, term)

	// Compute numerator = 2·z
	var num E6
	num.Double(api, z)

	// Compute result = num / denom
	var result E6
	result.DivUnchecked(api, num, denom)

	return result
}
