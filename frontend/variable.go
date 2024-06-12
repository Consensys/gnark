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

package frontend

import (
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/field/pool"
	
	"github.com/consensys/gnark/frontend/internal/expr"
)

// Variable represents a variable in the circuit. Any integer type (e.g. int, *big.Int, fr.Element)
// can be assigned to it. It is also allowed to set a base-10 encoded string representing an integer value.
// The only purpose of putting this definition here is to avoid the import cycles (cs/plonk <-> frontend) and (cs/r1cs <-> frontend)
type Variable interface{}

type Element [4]uint64

var qInvNeg uint64

// Field modulus q
var (
	q0 uint64
	q1 uint64
	q2 uint64
	q3 uint64
)

var _modulus big.Int // q stored as big.Int

// SetZero z = 0
func (z *Element) SetZero() *Element {
	z[0] = 0
	z[1] = 0
	z[2] = 0
	z[3] = 0
	return z
}

// rSquare where r is the Montgommery constant
// see section 2.3.2 of Tolga Acar's thesis
// https://www.microsoft.com/en-us/research/wp-content/uploads/1998/06/97Acar.pdf
var rSquare = Element{
}

const (
	Limbs = 4   // number of 64 bits words needed to represent a Element
	Bits  = 254 // number of bits needed to represent a Element
	Bytes = 32  // number of bytes needed to represent a Element
)

// fromMont converts z in place (i.e. mutates) from Montgomery to regular representation
// sets and returns z = z * 1
func (z *Element) fromMont() *Element {
	fromMont(z)
	return z
}

func fromMont(z *Element) {
	_fromMontGeneric(z)
}

func _fromMontGeneric(z *Element) {
	// the following lines implement z = z * 1
	// with a modified CIOS montgomery multiplication
	// see Mul for algorithm documentation
	{
		// m = z[0]n'[0] mod W
		m := z[0] * qInvNeg
		C := madd0(m, q0, z[0])
		C, z[0] = madd2(m, q1, z[1], C)
		C, z[1] = madd2(m, q2, z[2], C)
		C, z[2] = madd2(m, q3, z[3], C)
		z[3] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * qInvNeg
		C := madd0(m, q0, z[0])
		C, z[0] = madd2(m, q1, z[1], C)
		C, z[1] = madd2(m, q2, z[2], C)
		C, z[2] = madd2(m, q3, z[3], C)
		z[3] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * qInvNeg
		C := madd0(m, q0, z[0])
		C, z[0] = madd2(m, q1, z[1], C)
		C, z[1] = madd2(m, q2, z[2], C)
		C, z[2] = madd2(m, q3, z[3], C)
		z[3] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * qInvNeg
		C := madd0(m, q0, z[0])
		C, z[0] = madd2(m, q1, z[1], C)
		C, z[1] = madd2(m, q2, z[2], C)
		C, z[2] = madd2(m, q3, z[3], C)
		z[3] = C
	}

	// if z ⩾ q → z -= q
	if !z.smallerThanModulus() {
		var b uint64
		z[0], b = bits.Sub64(z[0], q0, 0)
		z[1], b = bits.Sub64(z[1], q1, b)
		z[2], b = bits.Sub64(z[2], q2, b)
		z[3], _ = bits.Sub64(z[3], q3, b)
	}
}

// smallerThanModulus returns true if z < q
// This is not constant time
func (z *Element) smallerThanModulus() bool {
	return (z[3] < q3 || (z[3] == q3 && (z[2] < q2 || (z[2] == q2 && (z[1] < q1 || (z[1] == q1 && (z[0] < q0)))))))
}

// madd0 hi = a*b + c (discards lo bits)
func madd0(a, b, c uint64) (hi uint64) {
	var carry, lo uint64
	hi, lo = bits.Mul64(a, b)
	_, carry = bits.Add64(lo, c, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	return
}

// madd1 hi, lo = a*b + c
func madd1(a, b, c uint64) (hi uint64, lo uint64) {
	var carry uint64
	hi, lo = bits.Mul64(a, b)
	lo, carry = bits.Add64(lo, c, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	return
}

// madd2 hi, lo = a*b + c + d
func madd2(a, b, c, d uint64) (hi uint64, lo uint64) {
	var carry uint64
	hi, lo = bits.Mul64(a, b)
	c, carry = bits.Add64(c, d, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	lo, carry = bits.Add64(lo, c, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	return
}

func madd3(a, b, c, d, e uint64) (hi uint64, lo uint64) {
	var carry uint64
	hi, lo = bits.Mul64(a, b)
	c, carry = bits.Add64(c, d, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	lo, carry = bits.Add64(lo, c, 0)
	hi, _ = bits.Add64(hi, e, carry)
	return
}
func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// BigEndian is the big-endian implementation of ByteOrder and AppendByteOrder.
var BigEndian bigEndian

type bigEndian struct{}

// Element interpret b is a big-endian 32-byte slice.
// If b encodes a value higher than q, Element returns error.
func (bigEndian) Element(b *[Bytes]byte) (Element, error) {
	var z Element
	z[0] = binary.BigEndian.Uint64((*b)[24:32])
	z[1] = binary.BigEndian.Uint64((*b)[16:24])
	z[2] = binary.BigEndian.Uint64((*b)[8:16])
	z[3] = binary.BigEndian.Uint64((*b)[0:8])

	if !z.smallerThanModulus() {
		return Element{}, errors.New("invalid fr.Element encoding")
	}

	z.toMont()
	return z, nil
}

// toMont converts z to Montgomery form
// sets and returns z = z * r²
func (z *Element) toMont() *Element {
	return z.Mul(z, &rSquare)
}

// Mul z = x * y (mod q)
//
// x and y must be less than q
func (z *Element) Mul(x, y *Element) *Element {

	// Implements CIOS multiplication -- section 2.3.2 of Tolga Acar's thesis
	// https://www.microsoft.com/en-us/research/wp-content/uploads/1998/06/97Acar.pdf
	//
	// The algorithm:
	//
	// for i=0 to N-1
	// 		C := 0
	// 		for j=0 to N-1
	// 			(C,t[j]) := t[j] + x[j]*y[i] + C
	// 		(t[N+1],t[N]) := t[N] + C
	//
	// 		C := 0
	// 		m := t[0]*q'[0] mod D
	// 		(C,_) := t[0] + m*q[0]
	// 		for j=1 to N-1
	// 			(C,t[j-1]) := t[j] + m*q[j] + C
	//
	// 		(C,t[N-1]) := t[N] + C
	// 		t[N] := t[N+1] + C
	//
	// → N is the number of machine words needed to store the modulus q
	// → D is the word size. For example, on a 64-bit architecture D is 2	64
	// → x[i], y[i], q[i] is the ith word of the numbers x,y,q
	// → q'[0] is the lowest word of the number -q⁻¹ mod r. This quantity is pre-computed, as it does not depend on the inputs.
	// → t is a temporary array of size N+2
	// → C, S are machine words. A pair (C,S) refers to (hi-bits, lo-bits) of a two-word number
	//
	// As described here https://hackmd.io/@gnark/modular_multiplication we can get rid of one carry chain and simplify:
	// (also described in https://eprint.iacr.org/2022/1400.pdf annex)
	//
	// for i=0 to N-1
	// 		(A,t[0]) := t[0] + x[0]*y[i]
	// 		m := t[0]*q'[0] mod W
	// 		C,_ := t[0] + m*q[0]
	// 		for j=1 to N-1
	// 			(A,t[j])  := t[j] + x[j]*y[i] + A
	// 			(C,t[j-1]) := t[j] + m*q[j] + C
	//
	// 		t[N-1] = C + A
	//
	// This optimization saves 5N + 2 additions in the algorithm, and can be used whenever the highest bit
	// of the modulus is zero (and not all of the remaining bits are set).

	var t0, t1, t2, t3 uint64
	var u0, u1, u2, u3 uint64
	{
		var c0, c1, c2 uint64
		v := x[0]
		u0, t0 = bits.Mul64(v, y[0])
		u1, t1 = bits.Mul64(v, y[1])
		u2, t2 = bits.Mul64(v, y[2])
		u3, t3 = bits.Mul64(v, y[3])
		t1, c0 = bits.Add64(u0, t1, 0)
		t2, c0 = bits.Add64(u1, t2, c0)
		t3, c0 = bits.Add64(u2, t3, c0)
		c2, _ = bits.Add64(u3, 0, c0)

		m := qInvNeg * t0

		u0, c1 = bits.Mul64(m, q0)
		_, c0 = bits.Add64(t0, c1, 0)
		u1, c1 = bits.Mul64(m, q1)
		t0, c0 = bits.Add64(t1, c1, c0)
		u2, c1 = bits.Mul64(m, q2)
		t1, c0 = bits.Add64(t2, c1, c0)
		u3, c1 = bits.Mul64(m, q3)

		t2, c0 = bits.Add64(0, c1, c0)
		u3, _ = bits.Add64(u3, 0, c0)
		t0, c0 = bits.Add64(u0, t0, 0)
		t1, c0 = bits.Add64(u1, t1, c0)
		t2, c0 = bits.Add64(u2, t2, c0)
		c2, _ = bits.Add64(c2, 0, c0)
		t2, c0 = bits.Add64(t3, t2, 0)
		t3, _ = bits.Add64(u3, c2, c0)

	}
	{
		var c0, c1, c2 uint64
		v := x[1]
		u0, c1 = bits.Mul64(v, y[0])
		t0, c0 = bits.Add64(c1, t0, 0)
		u1, c1 = bits.Mul64(v, y[1])
		t1, c0 = bits.Add64(c1, t1, c0)
		u2, c1 = bits.Mul64(v, y[2])
		t2, c0 = bits.Add64(c1, t2, c0)
		u3, c1 = bits.Mul64(v, y[3])
		t3, c0 = bits.Add64(c1, t3, c0)

		c2, _ = bits.Add64(0, 0, c0)
		t1, c0 = bits.Add64(u0, t1, 0)
		t2, c0 = bits.Add64(u1, t2, c0)
		t3, c0 = bits.Add64(u2, t3, c0)
		c2, _ = bits.Add64(u3, c2, c0)

		m := qInvNeg * t0

		u0, c1 = bits.Mul64(m, q0)
		_, c0 = bits.Add64(t0, c1, 0)
		u1, c1 = bits.Mul64(m, q1)
		t0, c0 = bits.Add64(t1, c1, c0)
		u2, c1 = bits.Mul64(m, q2)
		t1, c0 = bits.Add64(t2, c1, c0)
		u3, c1 = bits.Mul64(m, q3)

		t2, c0 = bits.Add64(0, c1, c0)
		u3, _ = bits.Add64(u3, 0, c0)
		t0, c0 = bits.Add64(u0, t0, 0)
		t1, c0 = bits.Add64(u1, t1, c0)
		t2, c0 = bits.Add64(u2, t2, c0)
		c2, _ = bits.Add64(c2, 0, c0)
		t2, c0 = bits.Add64(t3, t2, 0)
		t3, _ = bits.Add64(u3, c2, c0)

	}
	{
		var c0, c1, c2 uint64
		v := x[2]
		u0, c1 = bits.Mul64(v, y[0])
		t0, c0 = bits.Add64(c1, t0, 0)
		u1, c1 = bits.Mul64(v, y[1])
		t1, c0 = bits.Add64(c1, t1, c0)
		u2, c1 = bits.Mul64(v, y[2])
		t2, c0 = bits.Add64(c1, t2, c0)
		u3, c1 = bits.Mul64(v, y[3])
		t3, c0 = bits.Add64(c1, t3, c0)

		c2, _ = bits.Add64(0, 0, c0)
		t1, c0 = bits.Add64(u0, t1, 0)
		t2, c0 = bits.Add64(u1, t2, c0)
		t3, c0 = bits.Add64(u2, t3, c0)
		c2, _ = bits.Add64(u3, c2, c0)

		m := qInvNeg * t0

		u0, c1 = bits.Mul64(m, q0)
		_, c0 = bits.Add64(t0, c1, 0)
		u1, c1 = bits.Mul64(m, q1)
		t0, c0 = bits.Add64(t1, c1, c0)
		u2, c1 = bits.Mul64(m, q2)
		t1, c0 = bits.Add64(t2, c1, c0)
		u3, c1 = bits.Mul64(m, q3)

		t2, c0 = bits.Add64(0, c1, c0)
		u3, _ = bits.Add64(u3, 0, c0)
		t0, c0 = bits.Add64(u0, t0, 0)
		t1, c0 = bits.Add64(u1, t1, c0)
		t2, c0 = bits.Add64(u2, t2, c0)
		c2, _ = bits.Add64(c2, 0, c0)
		t2, c0 = bits.Add64(t3, t2, 0)
		t3, _ = bits.Add64(u3, c2, c0)

	}
	{
		var c0, c1, c2 uint64
		v := x[3]
		u0, c1 = bits.Mul64(v, y[0])
		t0, c0 = bits.Add64(c1, t0, 0)
		u1, c1 = bits.Mul64(v, y[1])
		t1, c0 = bits.Add64(c1, t1, c0)
		u2, c1 = bits.Mul64(v, y[2])
		t2, c0 = bits.Add64(c1, t2, c0)
		u3, c1 = bits.Mul64(v, y[3])
		t3, c0 = bits.Add64(c1, t3, c0)

		c2, _ = bits.Add64(0, 0, c0)
		t1, c0 = bits.Add64(u0, t1, 0)
		t2, c0 = bits.Add64(u1, t2, c0)
		t3, c0 = bits.Add64(u2, t3, c0)
		c2, _ = bits.Add64(u3, c2, c0)

		m := qInvNeg * t0

		u0, c1 = bits.Mul64(m, q0)
		_, c0 = bits.Add64(t0, c1, 0)
		u1, c1 = bits.Mul64(m, q1)
		t0, c0 = bits.Add64(t1, c1, c0)
		u2, c1 = bits.Mul64(m, q2)
		t1, c0 = bits.Add64(t2, c1, c0)
		u3, c1 = bits.Mul64(m, q3)

		t2, c0 = bits.Add64(0, c1, c0)
		u3, _ = bits.Add64(u3, 0, c0)
		t0, c0 = bits.Add64(u0, t0, 0)
		t1, c0 = bits.Add64(u1, t1, c0)
		t2, c0 = bits.Add64(u2, t2, c0)
		c2, _ = bits.Add64(c2, 0, c0)
		t2, c0 = bits.Add64(t3, t2, 0)
		t3, _ = bits.Add64(u3, c2, c0)

	}
	z[0] = t0
	z[1] = t1
	z[2] = t2
	z[3] = t3

	// if z ⩾ q → z -= q
	if !z.smallerThanModulus() {
		var b uint64
		z[0], b = bits.Sub64(z[0], q0, 0)
		z[1], b = bits.Sub64(z[1], q1, b)
		z[2], b = bits.Sub64(z[2], q2, b)
		z[3], _ = bits.Sub64(z[3], q3, b)
	}
	return z
}


func (bigEndian) PutElement(b *[Bytes]byte, e Element) {
	e.fromMont()
	binary.BigEndian.PutUint64((*b)[24:32], e[0])
	binary.BigEndian.PutUint64((*b)[16:24], e[1])
	binary.BigEndian.PutUint64((*b)[8:16], e[2])
	binary.BigEndian.PutUint64((*b)[0:8], e[3])
}

// Bytes returns the value of z as a big-endian byte array
func ToBytes(v Variable) (res [Bytes]byte) {
    BigEndian.PutElement(&res, v.(Element))
    return res
}

// FillBytes sets buf to the absolute value of x, storing it as a zero-extended
// big-endian byte slice, and returns buf.
//
// If the absolute value of x doesn't fit in buf, FillBytes will panic.
func FillBytes(x Variable, buf []byte) []byte {
	// Clear whole buffer. (This gets optimized into a memclr.)
	for i := range buf {
		buf[i] = 0
	}
	bytes := ToBytes(x)
	copy(buf, bytes[:])
	return buf
}

// Bytes returns the value of z as a big-endian byte array
func FromBytes(e []byte) Variable {
	z := new(Element)
	if len(e) == Bytes {
		// fast path
		v, err := BigEndian.Element((*[Bytes]byte)(e))
		if err == nil {
			*z = v
			return z
		}
	}

	// slow path.
	// get a big int from our pool
	vv := pool.BigInt.Get()
	vv.SetBytes(e)

	// set big int
	z.SetBigInt(vv)

	// put temporary object back in pool
	pool.BigInt.Put(vv)

	return z
}

// SetBigInt sets z to v and returns z
func (z *Element) SetBigInt(v *big.Int) *Element {
	z.SetZero()

	var zero big.Int

	// fast path
	c := v.Cmp(&_modulus)
	if c == 0 {
		// v == 0
		return z
	} else if c != 1 && v.Cmp(&zero) != -1 {
		// 0 < v < q
		return z.setBigInt(v)
	}

	// get temporary big int from the pool
	vv := pool.BigInt.Get()

	// copy input + modular reduction
	vv.Mod(v, &_modulus)

	// set big int byte value
	z.setBigInt(vv)

	// release object into pool
	pool.BigInt.Put(vv)
	return z
}

// setBigInt assumes 0 ⩽ v < q
func (z *Element) setBigInt(v *big.Int) *Element {
	vBits := v.Bits()

	if bits.UintSize == 64 {
		for i := 0; i < len(vBits); i++ {
			z[i] = uint64(vBits[i])
		}
	} else {
		for i := 0; i < len(vBits); i++ {
			if i%2 == 0 {
				z[i/2] = uint64(vBits[i])
			} else {
				z[i/2] |= uint64(vBits[i]) << 32
			}
		}
	}

	return z.toMont()
}

// Set z = x and returns z
func (z *Element) SetElement(x *Element) *Element {
	z[0] = x[0]
	z[1] = x[1]
	z[2] = x[2]
	z[3] = x[3]
	return z
}

func Set(z, x Variable) Variable {
	(*z.(*Element)).SetElement(x.(*Element))
	return z
}

// IsCanonical returns true if the Variable has been normalized in a (internal) LinearExpression
// by one of the constraint system builder. In other words, if the Variable is a circuit input OR
// returned by the API.
func IsCanonical(v Variable) bool {
	switch v.(type) {
	case expr.LinearExpression, *expr.LinearExpression, expr.Term, *expr.Term:
		return true
	}
	return false
}
