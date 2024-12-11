// Copyright 2020-2024 ConsenSys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by consensys/gnark-crypto DO NOT EDIT

package tinyfield

import "math/bits"

// MulBy3 x *= 3 (mod q)
func MulBy3(x *Element) {
	var y Element
	y.SetUint64(3)
	x.Mul(x, &y)
}

// MulBy5 x *= 5 (mod q)
func MulBy5(x *Element) {
	var y Element
	y.SetUint64(5)
	x.Mul(x, &y)
}

// MulBy13 x *= 13 (mod q)
func MulBy13(x *Element) {
	var y Element
	y.SetUint64(13)
	x.Mul(x, &y)
}

// Butterfly sets
//
//	a = a + b (mod q)
//	b = a - b (mod q)
func Butterfly(a, b *Element) {
	_butterflyGeneric(a, b)
}

func fromMont(z *Element) {
	_fromMontGeneric(z)
}

func reduce(z *Element) {
	_reduceGeneric(z)
}

// Mul z = x * y (mod q)
//
// x and y must be less than q
func (z *Element) Mul(x, y *Element) *Element {

	// In fact, since the modulus R fits on one register, the CIOS algorithm gets reduced to standard REDC (textbook Montgomery reduction):
	// hi, lo := x * y
	// m := (lo * qInvNeg) mod R
	// (*) r := (hi * R + lo + m * q) / R
	// reduce r if necessary

	// On the emphasized line, we get r = hi + (lo + m * q) / R
	// If we write hi2, lo2 = m * q then R | m * q - lo2 ⇒ R | (lo * qInvNeg) q - lo2 = -lo - lo2
	// This shows lo + lo2 = 0 mod R. i.e. lo + lo2 = 0 if lo = 0 and R otherwise.
	// Which finally gives (lo + m * q) / R = (lo + lo2 + R hi2) / R = hi2 + (lo+lo2) / R = hi2 + (lo != 0)
	// This "optimization" lets us do away with one MUL instruction on ARM architectures and is available for all q < R.

	var r uint64
	hi, lo := bits.Mul64(x[0], y[0])
	if lo != 0 {
		hi++ // x[0] * y[0] ≤ 2¹²⁸ - 2⁶⁵ + 1, meaning hi ≤ 2⁶⁴ - 2 so no need to worry about overflow
	}
	m := lo * qInvNeg
	hi2, _ := bits.Mul64(m, q)
	r, carry := bits.Add64(hi2, hi, 0)

	if carry != 0 || r >= q {
		// we need to reduce
		r -= q
	}
	z[0] = r

	return z
}

// Square z = x * x (mod q)
//
// x must be less than q
func (z *Element) Square(x *Element) *Element {
	// see Mul for algorithm documentation

	// In fact, since the modulus R fits on one register, the CIOS algorithm gets reduced to standard REDC (textbook Montgomery reduction):
	// hi, lo := x * y
	// m := (lo * qInvNeg) mod R
	// (*) r := (hi * R + lo + m * q) / R
	// reduce r if necessary

	// On the emphasized line, we get r = hi + (lo + m * q) / R
	// If we write hi2, lo2 = m * q then R | m * q - lo2 ⇒ R | (lo * qInvNeg) q - lo2 = -lo - lo2
	// This shows lo + lo2 = 0 mod R. i.e. lo + lo2 = 0 if lo = 0 and R otherwise.
	// Which finally gives (lo + m * q) / R = (lo + lo2 + R hi2) / R = hi2 + (lo+lo2) / R = hi2 + (lo != 0)
	// This "optimization" lets us do away with one MUL instruction on ARM architectures and is available for all q < R.

	var r uint64
	hi, lo := bits.Mul64(x[0], x[0])
	if lo != 0 {
		hi++ // x[0] * y[0] ≤ 2¹²⁸ - 2⁶⁵ + 1, meaning hi ≤ 2⁶⁴ - 2 so no need to worry about overflow
	}
	m := lo * qInvNeg
	hi2, _ := bits.Mul64(m, q)
	r, carry := bits.Add64(hi2, hi, 0)

	if carry != 0 || r >= q {
		// we need to reduce
		r -= q
	}
	z[0] = r

	return z
}
