// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// verifyScalarDecomposition checks s1 + s2*scalar ≡ 0 (mod r) using emulated
// arithmetic to avoid native field overflow. The sign bit controls whether
// the relation is s1 + s2*scalar or s1 - s2*scalar.
//
// s1 and s2 are range-checked to nBits via ToBinary inside this function.
// Returns the bit decompositions of s1 and s2.
func verifyScalarDecomposition(
	api frontend.API,
	s1, s2, bit, scalar frontend.Variable,
	curve *CurveParams,
) (s1Bits, s2Bits []frontend.Variable) {
	r := curve.Order
	n := (r.BitLen() + 1) / 2

	// Range-check s1, s2 via ToBinary
	s1Bits = api.ToBinary(s1, n)
	s2Bits = api.ToBinary(s2, n)

	// Dispatch to the correct emulated field based on the curve order
	switch {
	case r.BitLen() <= 253 && r.Cmp(edBN254Order{}.Modulus()) == 0:
		verifyDecompEmulated[edBN254Order](api, s1, s2, bit, scalar, s1Bits, s2Bits, r)
	case r.BitLen() <= 253 && r.Cmp(edBLS12381Order{}.Modulus()) == 0:
		verifyDecompEmulated[edBLS12381Order](api, s1, s2, bit, scalar, s1Bits, s2Bits, r)
	case r.BitLen() <= 253 && r.Cmp(edBandersnatchOrder{}.Modulus()) == 0:
		verifyDecompEmulated[edBandersnatchOrder](api, s1, s2, bit, scalar, s1Bits, s2Bits, r)
	case r.BitLen() <= 253 && r.Cmp(edBLS12377Order{}.Modulus()) == 0:
		verifyDecompEmulated[edBLS12377Order](api, s1, s2, bit, scalar, s1Bits, s2Bits, r)
	case r.Cmp(edBW6761Order{}.Modulus()) == 0:
		verifyDecompEmulated[edBW6761Order](api, s1, s2, bit, scalar, s1Bits, s2Bits, r)
	default:
		panic(fmt.Sprintf("unsupported twisted Edwards curve order: %s", r.String()))
	}

	return s1Bits, s2Bits
}

func verifyDecompEmulated[T emulated.FieldParams](
	api frontend.API,
	s1, s2, bit, scalar frontend.Variable,
	s1Bits, s2Bits []frontend.Variable,
	r *big.Int,
) {
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(fmt.Sprintf("failed to create emulated field: %v", err))
	}

	scalarBits := api.ToBinary(scalar, api.Compiler().FieldBitLen())

	s1Emu := f.FromBits(s1Bits...)
	s2Emu := f.FromBits(s2Bits...)
	scalarEmu := f.FromBits(scalarBits...)
	zero := f.Zero()

	// Compute s2 * scalar mod r
	s2s := f.Mul(s2Emu, scalarEmu)

	// Check: s1 ± s2*scalar ≡ 0 (mod r)
	// When bit=0: s1 + s2*scalar ≡ 0 → s1 ≡ -s2*scalar
	// When bit=1: s1 - s2*scalar ≡ 0 → s1 ≡ s2*scalar
	// Equivalently: s1 + Select(bit, -s2s, s2s) ≡ 0
	negS2s := f.Neg(s2s)
	term := f.Select(bit, negS2s, s2s)
	sum := f.Add(s1Emu, term)
	f.AssertIsEqual(sum, zero)

	// Ensure s2 is non-zero to prevent trivial decomposition.
	// When scalar=0, s2=0 is legitimate.
	scalarIsZero := api.IsZero(scalar)
	s2Check := f.Select(scalarIsZero, f.One(), s2Emu)
	f.AssertIsDifferent(s2Check, zero)
}

// verifyScalarDecompositionPair checks two independent decompositions:
// u1 + v1*s1 ≡ 0 (mod r) and u2 + v2*s2 ≡ 0 (mod r)
// Used by doubleBaseScalarMul3MSMLogUp.
func verifyScalarDecompositionPair(
	api frontend.API,
	u1, v1, bit1, s1 frontend.Variable,
	u2, v2, bit2, s2 frontend.Variable,
	curve *CurveParams,
) (u1Bits, v1Bits, u2Bits, v2Bits []frontend.Variable) {
	r := curve.Order
	n := (r.BitLen() + 1) / 2

	u1Bits = api.ToBinary(u1, n)
	v1Bits = api.ToBinary(v1, n)
	u2Bits = api.ToBinary(u2, n)
	v2Bits = api.ToBinary(v2, n)

	switch {
	case r.Cmp(edBN254Order{}.Modulus()) == 0:
		verifyDecompPairEmulated[edBN254Order](api, u1, v1, bit1, s1, u2, v2, bit2, s2, u1Bits, v1Bits, u2Bits, v2Bits, r)
	case r.Cmp(edBLS12381Order{}.Modulus()) == 0:
		verifyDecompPairEmulated[edBLS12381Order](api, u1, v1, bit1, s1, u2, v2, bit2, s2, u1Bits, v1Bits, u2Bits, v2Bits, r)
	case r.Cmp(edBandersnatchOrder{}.Modulus()) == 0:
		verifyDecompPairEmulated[edBandersnatchOrder](api, u1, v1, bit1, s1, u2, v2, bit2, s2, u1Bits, v1Bits, u2Bits, v2Bits, r)
	case r.Cmp(edBLS12377Order{}.Modulus()) == 0:
		verifyDecompPairEmulated[edBLS12377Order](api, u1, v1, bit1, s1, u2, v2, bit2, s2, u1Bits, v1Bits, u2Bits, v2Bits, r)
	case r.Cmp(edBW6761Order{}.Modulus()) == 0:
		verifyDecompPairEmulated[edBW6761Order](api, u1, v1, bit1, s1, u2, v2, bit2, s2, u1Bits, v1Bits, u2Bits, v2Bits, r)
	default:
		panic(fmt.Sprintf("unsupported twisted Edwards curve order: %s", r.String()))
	}

	return
}

func verifyDecompPairEmulated[T emulated.FieldParams](
	api frontend.API,
	u1, v1, bit1, s1 frontend.Variable,
	u2, v2, bit2, s2 frontend.Variable,
	u1Bits, v1Bits, u2Bits, v2Bits []frontend.Variable,
	r *big.Int,
) {
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(fmt.Sprintf("failed to create emulated field: %v", err))
	}

	nativeBits := api.Compiler().FieldBitLen()
	s1Bits := api.ToBinary(s1, nativeBits)
	s2Bits := api.ToBinary(s2, nativeBits)

	u1Emu := f.FromBits(u1Bits...)
	v1Emu := f.FromBits(v1Bits...)
	s1Emu := f.FromBits(s1Bits...)
	u2Emu := f.FromBits(u2Bits...)
	v2Emu := f.FromBits(v2Bits...)
	s2Emu := f.FromBits(s2Bits...)
	zero := f.Zero()

	// Check: u1 ± v1*s1 ≡ 0 (mod r)
	v1s1 := f.Mul(v1Emu, s1Emu)
	negV1s1 := f.Neg(v1s1)
	term1 := f.Select(bit1, negV1s1, v1s1)
	sum1 := f.Add(u1Emu, term1)
	f.AssertIsEqual(sum1, zero)

	// Ensure v1 non-zero (when s1 != 0)
	s1IsZero := api.IsZero(s1)
	v1Check := f.Select(s1IsZero, f.One(), v1Emu)
	f.AssertIsDifferent(v1Check, zero)

	// Check: u2 ± v2*s2 ≡ 0 (mod r)
	v2s2 := f.Mul(v2Emu, s2Emu)
	negV2s2 := f.Neg(v2s2)
	term2 := f.Select(bit2, negV2s2, v2s2)
	sum2 := f.Add(u2Emu, term2)
	f.AssertIsEqual(sum2, zero)

	// Ensure v2 non-zero (when s2 != 0)
	s2IsZero := api.IsZero(s2)
	v2Check := f.Select(s2IsZero, f.One(), v2Emu)
	f.AssertIsDifferent(v2Check, zero)
}

// verifyScalarDecomposition6D checks the 6D decomposition for doubleBaseScalarMul6MSMLogUp.
// Verifies: s_i * (z + λ*t) ≡ x_i + λ*y_i (mod r) for i=1,2
// All verification is done in emulated arithmetic over the curve order to avoid overflow.
func verifyScalarDecomposition6D(
	api frontend.API,
	s1, s2 frontend.Variable,
	absX1, absY1, absX2, absY2, absZ, absT frontend.Variable,
	signX1, signY1, signX2, signY2, signZ, signT frontend.Variable,
	curve *CurveParams,
	endo *EndoParams,
) {
	r := curve.Order

	switch {
	case r.Cmp(edBandersnatchOrder{}.Modulus()) == 0:
		verify6DEmulated[edBandersnatchOrder](api, s1, s2, absX1, absY1, absX2, absY2, absZ, absT,
			signX1, signY1, signX2, signY2, signZ, signT, r, endo.Lambda)
	default:
		// Currently only Bandersnatch has an endomorphism. Add other cases as needed.
		panic(fmt.Sprintf("unsupported twisted Edwards curve order for 6D decomposition: %s", r.String()))
	}
}

func verify6DEmulated[T emulated.FieldParams](
	api frontend.API,
	s1, s2 frontend.Variable,
	absX1, absY1, absX2, absY2, absZ, absT frontend.Variable,
	signX1, signY1, signX2, signY2, signZ, signT frontend.Variable,
	r, lambda *big.Int,
) {
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(fmt.Sprintf("failed to create emulated field: %v", err))
	}

	orderBits := r.BitLen()
	nBits := (orderBits + 2) / 3

	// Range check the sub-scalars
	api.ToBinary(absX1, nBits)
	api.ToBinary(absY1, nBits)
	api.ToBinary(absX2, nBits)
	api.ToBinary(absY2, nBits)
	api.ToBinary(absZ, nBits)
	api.ToBinary(absT, nBits)

	// Convert to emulated elements with signs
	absX1Emu := f.FromBits(api.ToBinary(absX1, nBits)...)
	absY1Emu := f.FromBits(api.ToBinary(absY1, nBits)...)
	absX2Emu := f.FromBits(api.ToBinary(absX2, nBits)...)
	absY2Emu := f.FromBits(api.ToBinary(absY2, nBits)...)
	absZEmu := f.FromBits(api.ToBinary(absZ, nBits)...)
	absTEmu := f.FromBits(api.ToBinary(absT, nBits)...)

	lambdaEmu := f.NewElement(lambda)
	zero := f.Zero()

	// Signed values in emulated field
	x1Emu := f.Select(signX1, f.Neg(absX1Emu), absX1Emu)
	y1Emu := f.Select(signY1, f.Neg(absY1Emu), absY1Emu)
	x2Emu := f.Select(signX2, f.Neg(absX2Emu), absX2Emu)
	y2Emu := f.Select(signY2, f.Neg(absY2Emu), absY2Emu)
	zEmu := f.Select(signZ, f.Neg(absZEmu), absZEmu)
	tEmu := f.Select(signT, f.Neg(absTEmu), absTEmu)

	// d = z + λ*t (mod r)
	dComputed := f.Add(zEmu, f.Mul(lambdaEmu, tEmu))

	// n1 = x1 + λ*y1 (mod r)
	n1Computed := f.Add(x1Emu, f.Mul(lambdaEmu, y1Emu))

	// n2 = x2 + λ*y2 (mod r)
	n2Computed := f.Add(x2Emu, f.Mul(lambdaEmu, y2Emu))

	// s1 * d ≡ n1 (mod r)
	nativeBits := api.Compiler().FieldBitLen()
	s1Bits := api.ToBinary(s1, nativeBits)
	s1Emu := f.FromBits(s1Bits...)
	f.AssertIsEqual(f.Mul(s1Emu, dComputed), n1Computed)

	// s2 * d ≡ n2 (mod r)
	s2Bits := api.ToBinary(s2, nativeBits)
	s2Emu := f.FromBits(s2Bits...)
	f.AssertIsEqual(f.Mul(s2Emu, dComputed), n2Computed)

	// Ensure d non-zero (unless both scalars are zero)
	bothZero := api.And(api.IsZero(s1), api.IsZero(s2))
	dCheck := f.Select(bothZero, f.One(), dComputed)
	f.AssertIsDifferent(dCheck, zero)
}
