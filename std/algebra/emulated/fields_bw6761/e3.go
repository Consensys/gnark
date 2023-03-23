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

package fields_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BW6761Fp]
type BaseField = emulated.Element[emulated.BW6761Fp]

type E3 struct {
	A0, A1, A2 BaseField
}

type Ext3 struct {
	Fp *curveF
}

func (e Ext3) Reduce(x *E3) *E3 {
	var z E3
	z.A0 = *e.Fp.Reduce(&x.A0)
	z.A1 = *e.Fp.Reduce(&x.A1)
	z.A2 = *e.Fp.Reduce(&x.A2)
	return &z
}

func NewExt3(baseField *curveF) *Ext3 {
	return &Ext3{
		Fp: baseField,
	}
}

// SetZero sets an *E3 elmt to zero
func (e Ext3) Zero() *E3 {
	a0 := e.Fp.Zero()
	a1 := e.Fp.Zero()
	a2 := e.Fp.Zero()
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// One sets z to 1 in Montgomery form and returns z
func (e Ext3) One() *E3 {
	a0 := e.Fp.One()
	a1 := e.Fp.Zero()
	a2 := e.Fp.Zero()
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Neg negates the *E3 number
func (e Ext3) Neg(x *E3) *E3 {
	a0 := e.Fp.Neg(&x.A0)
	a1 := e.Fp.Neg(&x.A1)
	a2 := e.Fp.Neg(&x.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Add adds two elements of *E3
func (e Ext3) Add(x, y *E3) *E3 {
	a0 := e.Fp.Add(&x.A0, &y.A0)
	a1 := e.Fp.Add(&x.A1, &y.A1)
	a2 := e.Fp.Add(&x.A2, &y.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Sub two elements of *E3
func (e Ext3) Sub(x, y *E3) *E3 {
	a0 := e.Fp.Sub(&x.A0, &y.A0)
	a1 := e.Fp.Sub(&x.A1, &y.A1)
	a2 := e.Fp.Sub(&x.A2, &y.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Double doubles an element in *E3
func (e Ext3) Double(x *E3) *E3 {
	//two := big.NewInt(2)
	a0 := e.Fp.Add(&x.A0, &x.A0)
	a1 := e.Fp.Add(&x.A1, &x.A1)
	a2 := e.Fp.Add(&x.A2, &x.A2)
	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

func MulByNonResidue(fp *curveF, x *BaseField) *BaseField {

	z := fp.Neg(x)
	z = fp.Add(z, z)
	z = fp.Add(z, z)
	//nonResidue := emulated.NewElement[emulated.BW6761Fp](-4)
	//z := Fp.Mul(x, &nonResidue)
	//z := Fp.MulConst(x, big.NewInt(-4))
	//z := Fp.Neg(Fp.MulConst(x, big.NewInt(4)))
	return z
}

// Conjugate conjugates an element in *E3
func (e Ext3) Conjugate(x *E3) *E3 {
	a1 := e.Fp.Neg(&x.A1)
	return &E3{
		A0: x.A0,
		A1: *a1,
		A2: x.A2,
	}
}

// MulByElement multiplies an element in *E3 by an element in Fp
func (e Ext3) MulByElement(x *E3, y *BaseField) *E3 {
	a0 := e.Fp.Mul(&x.A0, y)
	a1 := e.Fp.Mul(&x.A1, y)
	a2 := e.Fp.Mul(&x.A2, y)
	z := &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
	return z
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e Ext3) MulBy01(z *E3, c0, c1 *BaseField) *E3 {

	a := e.Fp.Mul(&z.A0, c0)
	b := e.Fp.Mul(&z.A1, c1)

	tmp := e.Fp.Add(&z.A1, &z.A2)
	t0 := e.Fp.Mul(c1, tmp)
	t0 = e.Fp.Sub(t0, b)
	t0 = MulByNonResidue(e.Fp, t0)
	t0 = e.Fp.Add(t0, a)

	tmp = e.Fp.Add(&z.A0, &z.A2)
	t2 := e.Fp.Mul(c0, tmp)
	t2 = e.Fp.Sub(t2, a)
	t2 = e.Fp.Add(t2, b)

	t1 := e.Fp.Add(c0, c1)
	tmp = e.Fp.Add(&z.A0, &z.A1)
	t1 = e.Fp.Mul(t1, tmp)
	t1 = e.Fp.Sub(t1, a)
	t1 = e.Fp.Sub(t1, b)

	return &E3{
		A0: *t0,
		A1: *t1,
		A2: *t2,
	}
}

// MulBy1 multiplication of E6 by sparse element (0, c1, 0)
func (e Ext3) MulBy1(z *E3, c1 BaseField) *E3 {

	b := e.Fp.Mul(&z.A1, &c1)

	tmp := e.Fp.Add(&z.A1, &z.A2)
	t0 := e.Fp.Mul(&c1, tmp)
	t0 = e.Fp.Sub(t0, b)
	t0 = MulByNonResidue(e.Fp, t0)

	tmp = e.Fp.Add(&z.A0, &z.A1)
	t1 := e.Fp.Mul(&c1, tmp)
	t1 = e.Fp.Sub(t1, b)

	return &E3{
		A0: *t0,
		A1: *t1,
		A2: *b,
	}
}

// Mul sets z to the *E3-product of x,y, returns z
func (e Ext3) Mul(x, y *E3) *E3 {
	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	t0 := e.Fp.Mul(&x.A0, &y.A0)
	t1 := e.Fp.Mul(&x.A1, &y.A1)
	t2 := e.Fp.Mul(&x.A2, &y.A2)

	c0 := e.Fp.Add(&x.A1, &x.A2)
	tmp := e.Fp.Add(&y.A1, &y.A2)
	c0 = e.Fp.Mul(c0, tmp)
	c0 = e.Fp.Sub(c0, t1)
	c0 = e.Fp.Sub(c0, t2)
	c0 = MulByNonResidue(e.Fp, c0)

	tmp = e.Fp.Add(&x.A0, &x.A2)
	c2 := e.Fp.Add(&y.A0, &y.A2)
	c2 = e.Fp.Mul(c2, tmp)
	c2 = e.Fp.Sub(c2, t0)
	c2 = e.Fp.Sub(c2, t2)

	c1 := e.Fp.Add(&x.A0, &x.A1)
	tmp = e.Fp.Add(&y.A0, &y.A1)
	c1 = e.Fp.Mul(c1, tmp)
	c1 = e.Fp.Sub(c1, t0)
	c1 = e.Fp.Sub(c1, t1)
	t2 = MulByNonResidue(e.Fp, t2)

	a0 := e.Fp.Add(c0, t0)
	a1 := e.Fp.Add(c1, t2)
	a2 := e.Fp.Add(c2, t1)

	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Square sets z to the *E3-product of x,x, returns z
func (e Ext3) Square(x *E3) *E3 {

	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf

	c6 := e.Fp.Add(&x.A1, &x.A1)
	c4 := e.Fp.Mul(&x.A0, c6) // x.A0 * xA1 * 2
	c5 := e.Fp.Mul(&x.A2, &x.A2)
	c1 := MulByNonResidue(e.Fp, c5)
	c1 = e.Fp.Add(c1, c4)
	c2 := e.Fp.Sub(c4, c5)

	c3 := e.Fp.Mul(&x.A0, &x.A0)
	c4 = e.Fp.Sub(&x.A0, &x.A1)
	c4 = e.Fp.Add(c4, &x.A2)
	c5 = e.Fp.Mul(c6, &x.A2) // x.A1 * xA2 * 2
	c4 = e.Fp.Mul(c4, c4)
	c0 := MulByNonResidue(e.Fp, c5)
	c4 = e.Fp.Add(c4, c5)
	c4 = e.Fp.Sub(c4, c3)

	a0 := e.Fp.Add(c0, c3)
	a1 := c1
	a2 := e.Fp.Add(c2, c4)

	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// Inverse an element in E3
func (e Ext3) Inverse(x *E3) *E3 {
	// Algorithm 17 from https://eprint.iacr.org/2010/354.pdf
	// step 9 is wrong in the paper it's t1-t4
	t0 := e.Fp.Mul(&x.A0, &x.A0)
	t1 := e.Fp.Mul(&x.A1, &x.A1)
	t2 := e.Fp.Mul(&x.A2, &x.A2)
	t3 := e.Fp.Mul(&x.A0, &x.A1)
	t4 := e.Fp.Mul(&x.A0, &x.A2)
	t5 := e.Fp.Mul(&x.A1, &x.A2)
	c0 := MulByNonResidue(e.Fp, t5)
	c0 = e.Fp.Neg(c0)
	c0 = e.Fp.Add(c0, t0)
	c1 := MulByNonResidue(e.Fp, t2)
	c1 = e.Fp.Sub(c1, t3)
	c2 := e.Fp.Sub(t1, t4)
	// reduce first
	c0 = e.Fp.Reduce(c0)
	c1 = e.Fp.Reduce(c1)
	c2 = e.Fp.Reduce(c2)

	t6 := e.Fp.Mul(&x.A0, c0)
	d1 := e.Fp.Mul(&x.A2, c1)
	d2 := e.Fp.Mul(&x.A1, c2)
	d1 = e.Fp.Add(d1, d2)
	d1 = MulByNonResidue(e.Fp, d1)
	t6 = e.Fp.Add(t6, d1)
	t6 = e.Fp.Inverse(t6)

	a0 := e.Fp.Mul(c0, t6)
	a1 := e.Fp.Mul(c1, t6)
	a2 := e.Fp.Mul(c2, t6)

	return &E3{
		A0: *a0,
		A1: *a1,
		A2: *a2,
	}
}

// MulByNonResidue mul x by (0,1,0)
func (e Ext3) MulByNonResidue(x *E3) *E3 {
	z := &E3{
		A0: x.A2,
		A1: x.A0,
		A2: x.A1,
	}
	z.A0 = *MulByNonResidue(e.Fp, &z.A0)
	return z
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e Ext3) AssertIsEqual(a, b *E3) {
	e.Fp.AssertIsEqual(&a.A0, &b.A0)
	e.Fp.AssertIsEqual(&a.A1, &b.A1)
	e.Fp.AssertIsEqual(&a.A2, &b.A2)
}

func (e Ext3) Set(x *E3) *E3 {
	return &E3{
		A0: x.A0,
		A1: x.A1,
		A2: x.A2,
	}
}

// Equal returns true if z equals x, fasle otherwise
func (e Ext3) Equal(a, b *E3) {
	e.Fp.AssertIsEqual(&a.A0, &b.A0)
	e.Fp.AssertIsEqual(&a.A1, &b.A1)
	e.Fp.AssertIsEqual(&a.A2, &b.A2)
}

func NewE3(a bw6761.E3) E3 {
	return E3{
		A0: emulated.ValueOf[emulated.BW6761Fp](a.A0),
		A1: emulated.ValueOf[emulated.BW6761Fp](a.A1),
		A2: emulated.ValueOf[emulated.BW6761Fp](a.A2),
	}
}
