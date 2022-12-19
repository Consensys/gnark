/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package pairing_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BW6761Fp]
type baseField = emulated.Element[emulated.BW6761Fp]

type E3 struct {
	A0, A1, A2 baseField
}

type ext3 struct {
	fp *curveF
}

func NewExt3(baseField *curveF) *ext3 {
	return &ext3{
		fp: baseField,
	}
}

// SetZero sets an *E3 elmt to zero
func (e ext3) Zero() *E3 {
	a0 := e.fp.Zero()
	a1 := e.fp.Zero()
	a2 := e.fp.Zero()
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// One sets z to 1 in Montgomery form and returns z
func (e ext3) One() *E3 {
	a0 := e.fp.One()
	a1 := e.fp.Zero()
	a2 := e.fp.Zero()
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Neg negates the *E3 number
func (e ext3) Neg(x *E3) *E3 {
	a0 := e.fp.Neg(&x.A0)
	a1 := e.fp.Neg(&x.A1)
	a2 := e.fp.Neg(&x.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Add adds two elements of *E3
func (e ext3) Add(x, y *E3) *E3 {
	a0 := e.fp.Add(&x.A0, &y.A0)
	a1 := e.fp.Add(&x.A1, &y.A1)
	a2 := e.fp.Add(&x.A2, &y.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Sub two elements of *E3
func (e ext3) Sub(x, y *E3) *E3 {
	a0 := e.fp.Sub(&x.A0, &y.A0)
	a1 := e.fp.Sub(&x.A1, &y.A1)
	a2 := e.fp.Sub(&x.A2, &y.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Double doubles an element in *E3
func (e ext3) Double(x *E3) *E3 {
	a0 := e.fp.Add(&x.A0, &x.A0)
	a1 := e.fp.Add(&x.A1, &x.A1)
	a2 := e.fp.Add(&x.A2, &x.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

func MulByNonResidue(fp *curveF, x *baseField) *baseField {
	z := fp.Add(x, x)
	z = fp.Add(z, z)
	z = fp.Neg(z)
	return z
}

// Conjugate conjugates an element in *E3
func (e ext3) Conjugate(x *E3) *E3 {
	a1 := e.fp.Neg(&x.A1)
	return &E3{
		A0: x.A0,
		A1: *a1,
		A2: x.A2,
	}
}

// MulByElement multiplies an element in *E3 by an element in fp
func (e ext3) MulByElement(x *E3, y *baseField) *E3 {
	_y := *y
	a0 := e.fp.Mul(&x.A0, &_y)
	a1 := e.fp.Mul(&x.A1, &_y)
	a2 := e.fp.Mul(&x.A2, &_y)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e ext3) MulBy01(z *E3, c0, c1 *baseField) *E3 {

	a := e.fp.Mul(&z.A0, c0)
	b := e.fp.Mul(&z.A1, c1)

	tmp := e.fp.Add(&z.A1, &z.A2)
	t0 := e.fp.Mul(c1, tmp)
	t0 = e.fp.Sub(t0, b)
	t0 = MulByNonResidue(e.fp, t0)
	t0 = e.fp.Add(t0, a)

	tmp = e.fp.Add(&z.A0, &z.A2)
	t2 := e.fp.Mul(c0, tmp)
	t2 = e.fp.Sub(t2, a)
	t2 = e.fp.Add(t2, b)

	t1 := e.fp.Add(c0, c1)
	tmp = e.fp.Add(&z.A0, &z.A1)
	t1 = e.fp.Mul(t1, tmp)
	t1 = e.fp.Sub(t1, a)
	t1 = e.fp.Sub(t1, b)

	return &E3{
		A0: *t0,
		A1: *t1,
		A2: *t2,
	}
}

// MulBy1 multiplication of E6 by sparse element (0, c1, 0)
func (e ext3) MulBy1(z *E3, c1 baseField) *E3 {

	b := e.fp.Mul(&z.A1, &c1)

	tmp := e.fp.Add(&z.A1, &z.A2)
	t0 := e.fp.Mul(&c1, tmp)
	t0 = e.fp.Sub(t0, b)
	t0 = MulByNonResidue(e.fp, t0)

	tmp = e.fp.Add(&z.A0, &z.A1)
	t1 := e.fp.Mul(&c1, tmp)
	t1 = e.fp.Sub(t1, b)

	return &E3{
		A0: *t0,
		A1: *t1,
		A2: *b,
	}
}

// Mul sets z to the *E3-product of x,y, returns z
func (e ext3) Mul(x, y *E3) *E3 {
	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	t0 := e.fp.Mul(&x.A0, &y.A0)
	t1 := e.fp.Mul(&x.A1, &y.A1)
	t2 := e.fp.Mul(&x.A2, &y.A2)

	c0 := e.fp.Add(&x.A1, &x.A2)
	tmp := e.fp.Add(&y.A1, &y.A2)
	c0 = e.fp.Mul(c0, tmp)
	c0 = e.fp.Sub(c0, t1)
	c0 = e.fp.Sub(c0, t2)
	c0 = MulByNonResidue(e.fp, c0)

	tmp = e.fp.Add(&x.A0, &x.A2)
	c2 := e.fp.Add(&y.A0, &y.A2)
	c2 = e.fp.Mul(c2, tmp)
	c2 = e.fp.Sub(c2, t0)
	c2 = e.fp.Sub(c2, t2)

	c1 := e.fp.Add(&x.A0, &x.A1)
	tmp = e.fp.Add(&y.A0, &y.A1)
	c1 = e.fp.Mul(c1, tmp)
	c1 = e.fp.Sub(c1, t0)
	c1 = e.fp.Sub(c1, t1)
	t2 = MulByNonResidue(e.fp, t2)

	a0 := e.fp.Add(c0, t0)
	a1 := e.fp.Add(c1, t2)
	a2 := e.fp.Add(c2, t1)

	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Square sets z to the *E3-product of x,x, returns z
func (e ext3) Square(x *E3) *E3 {

	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf

	c6 := e.fp.Add(&x.A1, &x.A1)
	c4 := e.fp.Mul(&x.A0, c6) // x.A0 * xA1 * 2
	c5 := e.fp.Mul(&x.A2, &x.A2)
	c1 := MulByNonResidue(e.fp, c5)
	c1 = e.fp.Add(c1, c4)
	c2 := e.fp.Sub(c4, c5)

	c3 := e.fp.Mul(&x.A0, &x.A0)
	c4 = e.fp.Sub(&x.A0, &x.A1)
	c4 = e.fp.Add(c4, &x.A2)
	c5 = e.fp.Mul(c6, &x.A2) // x.A1 * xA2 * 2
	c4 = e.fp.Mul(c4, c4)
	c0 := MulByNonResidue(e.fp, c5)
	c4 = e.fp.Add(c4, c5)
	c4 = e.fp.Sub(c4, c3)

	a0 := e.fp.Add(c0, c3)
	a1 := c1
	a2 := e.fp.Add(c2, c4)

	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Inverse an element in E3
func (e ext3) Inverse(x *E3) *E3 {
	// Algorithm 17 from https://eprint.iacr.org/2010/354.pdf
	// step 9 is wrong in the paper it's t1-t4
	t0 := e.fp.Mul(&x.A0, &x.A0)
	t1 := e.fp.Mul(&x.A1, &x.A1)
	t2 := e.fp.Mul(&x.A2, &x.A2)
	t3 := e.fp.Mul(&x.A0, &x.A1)
	t4 := e.fp.Mul(&x.A0, &x.A2)
	t5 := e.fp.Mul(&x.A1, &x.A2)
	c0 := MulByNonResidue(e.fp, t5)
	c0 = e.fp.Neg(c0)
	c0 = e.fp.Add(c0, t0)
	c1 := MulByNonResidue(e.fp, t2)
	c1 = e.fp.Sub(c1, t3)
	c2 := e.fp.Sub(t1, t4)
	t6 := e.fp.Mul(&x.A0, c0)
	d1 := e.fp.Mul(&x.A2, c1)
	d2 := e.fp.Mul(&x.A1, c2)
	d1 = e.fp.Add(d1, d2)
	d1 = MulByNonResidue(e.fp, d1)
	t6 = e.fp.Add(t6, d1)
	t6 = e.fp.Inverse(t6)

	a0 := e.fp.Mul(c0, t6)
	a1 := e.fp.Mul(c1, t6)
	a2 := e.fp.Mul(c2, t6)

	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// MulByNonResidue mul x by (0,1,0)
func (e ext3) MulByNonResidue(x *E3) *E3 {
	z := &E3{
		A0: x.A2,
		A1: x.A0,
		A2: x.A1,
	}
	z.A0 = *MulByNonResidue(e.fp, &z.A0)
	return z
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e ext3) AssertIsEqual(a, b *E3) {
	e.fp.AssertIsEqual(&a.A0, &b.A0)
	e.fp.AssertIsEqual(&a.A1, &b.A1)
	e.fp.AssertIsEqual(&a.A2, &b.A2)
}

func (e ext3) Set(x *E3) *E3 {
	return &E3{
		A0: x.A0,
		A1: x.A1,
		A2: x.A2,
	}
}

// Equal returns true if z equals x, fasle otherwise
func (e ext3) Equal(a, b *E3) {
	e.fp.AssertIsEqual(&a.A0, &b.A0)
	e.fp.AssertIsEqual(&a.A1, &b.A1)
	e.fp.AssertIsEqual(&a.A2, &b.A2)
}

func NewE3(a bw6761.E3) E3 {
	return E3{
		A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
		A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
		A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
	}
}
