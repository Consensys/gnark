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
func TorusSquare(api frontend.API, y E6, hint E6) E6 {
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

	// Verify: hint · denom = num
	var check E6
	check.Mul(api, hint, denom)
	check.AssertIsEqual(api, num)

	return hint
}

// TorusMul computes multiplication in torus representation
// Input: y1, y2 ∈ E6 representing x1, x2 ∈ T₆
// Output: y' ∈ E6 representing x1·x2 ∈ T₆
// Formula: y' = (y1 + y2) / (1 + y1·y2·v)
func TorusMul(api frontend.API, y1, y2 E6, hint E6) E6 {
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

	// Verify: hint · denom = num
	var check E6
	check.Mul(api, hint, denom)
	check.AssertIsEqual(api, num)

	return hint
}

// TorusMulBy01 computes multiplication by sparse element (y0, y1, 0) in torus
// This is used for line multiplication where the line projects to (-c3, -c4, 0)
func TorusMulBy01(api frontend.API, y E6, l0, l1 E2, hint E6) E6 {
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

	// Verify: hint · denom = num
	var check E6
	check.Mul(api, hint, denom)
	check.AssertIsEqual(api, num)

	return hint
}

// TorusSquareWithHint computes the square in torus representation using hints
func TorusSquareWithHint(api frontend.API, y E6) E6 {
	// Get hint for result
	res, err := api.NewHint(torusSquareHint, 6,
		y.B0.A0, y.B0.A1, y.B1.A0, y.B1.A1, y.B2.A0, y.B2.A1)
	if err != nil {
		panic(err)
	}
	var hint E6
	hint.B0.A0 = res[0]
	hint.B0.A1 = res[1]
	hint.B1.A0 = res[2]
	hint.B1.A1 = res[3]
	hint.B2.A0 = res[4]
	hint.B2.A1 = res[5]

	return TorusSquare(api, y, hint)
}

// TorusMulWithHint computes multiplication of two dense elements in torus using hints
func TorusMulWithHint(api frontend.API, y1, y2 E6) E6 {
	// Get hint for result
	res, err := api.NewHint(torusMulHint, 6,
		y1.B0.A0, y1.B0.A1, y1.B1.A0, y1.B1.A1, y1.B2.A0, y1.B2.A1,
		y2.B0.A0, y2.B0.A1, y2.B1.A0, y2.B1.A1, y2.B2.A0, y2.B2.A1)
	if err != nil {
		panic(err)
	}
	var hint E6
	hint.B0.A0 = res[0]
	hint.B0.A1 = res[1]
	hint.B1.A0 = res[2]
	hint.B1.A1 = res[3]
	hint.B2.A0 = res[4]
	hint.B2.A1 = res[5]

	return TorusMul(api, y1, y2, hint)
}

// TorusMulBy01WithHint computes multiplication by sparse element using hints
func TorusMulBy01WithHint(api frontend.API, y E6, l0, l1 E2) E6 {
	// Get hint for result
	res, err := api.NewHint(torusMulBy01Hint, 6,
		y.B0.A0, y.B0.A1, y.B1.A0, y.B1.A1, y.B2.A0, y.B2.A1,
		l0.A0, l0.A1, l1.A0, l1.A1)
	if err != nil {
		panic(err)
	}
	var hint E6
	hint.B0.A0 = res[0]
	hint.B0.A1 = res[1]
	hint.B1.A0 = res[2]
	hint.B1.A1 = res[3]
	hint.B2.A0 = res[4]
	hint.B2.A1 = res[5]

	return TorusMulBy01(api, y, l0, l1, hint)
}

// TorusDecompressWithHint converts torus representation back to E12 using hints
func TorusDecompressWithHint(api frontend.API, y E6) E12 {
	// Get hint for result
	res, err := api.NewHint(torusDecompressHint, 12,
		y.B0.A0, y.B0.A1, y.B1.A0, y.B1.A1, y.B2.A0, y.B2.A1)
	if err != nil {
		panic(err)
	}
	var hint E12
	hint.C0.B0.A0 = res[0]
	hint.C0.B0.A1 = res[1]
	hint.C0.B1.A0 = res[2]
	hint.C0.B1.A1 = res[3]
	hint.C0.B2.A0 = res[4]
	hint.C0.B2.A1 = res[5]
	hint.C1.B0.A0 = res[6]
	hint.C1.B0.A1 = res[7]
	hint.C1.B1.A0 = res[8]
	hint.C1.B1.A1 = res[9]
	hint.C1.B2.A0 = res[10]
	hint.C1.B2.A1 = res[11]

	return TorusDecompress(api, y, hint)
}

// TorusDecompress converts torus representation back to E12
// Input: y ∈ E6 representing x ∈ T₆
// Output: x ∈ E12 where x = (1 + y·w) / (1 - y·w)
// Verification: x · (1 - y·w) = (1 + y·w)
func TorusDecompress(api frontend.API, y E6, hint E12) E12 {
	// Verify: hint · (1 - y·w) = (1 + y·w)
	// (a + b·w) · (1 - y·w) = a - b·y·v + (b - a·y)·w
	// Should equal (1 + y·w), so:
	// a - b·y·v = 1
	// b - a·y = y

	// Compute hint.C0 - hint.C1·y·v
	var tmp E6
	tmp.Mul(api, hint.C1, y)
	tmp.MulByNonResidue(api, tmp)

	var lhs0 E6
	lhs0.Sub(api, hint.C0, tmp)

	// Compute hint.C1 - hint.C0·y
	var tmp2 E6
	tmp2.Mul(api, hint.C0, y)

	var lhs1 E6
	lhs1.Sub(api, hint.C1, tmp2)

	// Check lhs0 = 1
	var one E6
	one.SetOne()
	lhs0.AssertIsEqual(api, one)

	// Check lhs1 = y
	lhs1.AssertIsEqual(api, y)

	return hint
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

// TorusCompressWithHint computes compress(residueWitness) = C1 / (1 + C0)
// using a hint for the division result
func TorusCompressWithHint(api frontend.API, x E12) E6 {
	// Get hint for result: y = C1 / (1 + C0)
	res, err := api.NewHint(torusCompressHint, 6,
		x.C0.B0.A0, x.C0.B0.A1, x.C0.B1.A0, x.C0.B1.A1, x.C0.B2.A0, x.C0.B2.A1,
		x.C1.B0.A0, x.C1.B0.A1, x.C1.B1.A0, x.C1.B1.A1, x.C1.B2.A0, x.C1.B2.A1)
	if err != nil {
		panic(err)
	}
	var y E6
	y.B0.A0 = res[0]
	y.B0.A1 = res[1]
	y.B1.A0 = res[2]
	y.B1.A1 = res[3]
	y.B2.A0 = res[4]
	y.B2.A1 = res[5]

	// Verify: y · (1 + C0) = C1
	var one E6
	one.SetOne()
	var c0PlusOne E6
	c0PlusOne.Add(api, x.C0, one)
	var check E6
	check.Mul(api, y, c0PlusOne)
	check.AssertIsEqual(api, x.C1)

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

	// Compute result = num / denom using hint
	var result E6
	result.DivUnchecked(api, num, denom)

	return result
}
