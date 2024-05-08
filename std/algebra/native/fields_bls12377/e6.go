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

package fields_bls12377

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"

	"github.com/consensys/gnark/frontend"
)

// E6 element in a quadratic extension
type E6 struct {
	B0, B1, B2 E2
}

// SetZero returns a newly allocated element equal to 0
func (e *E6) SetZero() *E6 {
	e.B0.SetZero()
	e.B1.SetZero()
	e.B2.SetZero()
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E6) SetOne() *E6 {
	e.B0.SetOne()
	e.B1.SetZero()
	e.B2.SetZero()
	return e
}

func (e *E6) assign(e1 []frontend.Variable) {
	e.B0.A0 = e1[0]
	e.B0.A1 = e1[1]
	e.B1.A0 = e1[2]
	e.B1.A1 = e1[3]
	e.B2.A0 = e1[4]
	e.B2.A1 = e1[5]
}

// Double e6 elmt
func (e *E6) Double(api frontend.API, e1 E6) *E6 {
	e.B0.Double(api, e1.B0)
	e.B1.Double(api, e1.B1)
	e.B2.Double(api, e1.B2)
	return e
}

// Add creates a fp6elmt from fp elmts
func (e *E6) Add(api frontend.API, e1, e2 E6) *E6 {

	e.B0.Add(api, e1.B0, e2.B0)
	e.B1.Add(api, e1.B1, e2.B1)
	e.B2.Add(api, e1.B2, e2.B2)

	return e
}

// NewFp6Zero creates a new
func NewFp6Zero(api frontend.API) *E6 {
	return &E6{
		B0: E2{0, 0},
		B1: E2{0, 0},
		B2: E2{0, 0},
	}
}

// Sub creates a fp6elmt from fp elmts
func (e *E6) Sub(api frontend.API, e1, e2 E6) *E6 {

	e.B0.Sub(api, e1.B0, e2.B0)
	e.B1.Sub(api, e1.B1, e2.B1)
	e.B2.Sub(api, e1.B2, e2.B2)

	return e
}

// Neg negates an Fp6 elmt
func (e *E6) Neg(api frontend.API, e1 E6) *E6 {
	e.B0.Neg(api, e1.B0)
	e.B1.Neg(api, e1.B1)
	e.B2.Neg(api, e1.B2)
	return e
}

// Mul creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) Mul(api frontend.API, e1, e2 E6) *E6 {

	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var t0, t1, t2, c0, c1, c2, tmp E2
	t0.Mul(api, e1.B0, e2.B0)
	t1.Mul(api, e1.B1, e2.B1)
	t2.Mul(api, e1.B2, e2.B2)

	c0.Add(api, e1.B1, e1.B2)
	tmp.Add(api, e2.B1, e2.B2)
	c0.Mul(api, c0, tmp).
		Sub(api, c0, t1).
		Sub(api, c0, t2).
		MulByNonResidue(api, c0).
		Add(api, c0, t0)

	c1.Add(api, e1.B0, e1.B1)
	tmp.Add(api, e2.B0, e2.B1)
	c1.Mul(api, c1, tmp).
		Sub(api, c1, t0).
		Sub(api, c1, t1)
	tmp.MulByNonResidue(api, t2)
	c1.Add(api, c1, tmp)

	tmp.Add(api, e1.B0, e1.B2)
	c2.Add(api, e2.B0, e2.B2).
		Mul(api, c2, tmp).
		Sub(api, c2, t0).
		Sub(api, c2, t2).
		Add(api, c2, t1)

	e.B0 = c0
	e.B1 = c1
	e.B2 = c2

	return e
}

func (e *E6) Mul0By01(api frontend.API, a0, b0, b1 E2) *E6 {

	var t0, c1 E2

	t0.Mul(api, a0, b0)
	c1.Add(api, b0, b1)
	c1.Mul(api, c1, a0).Sub(api, c1, t0)

	e.B0 = t0
	e.B1 = c1
	e.B2 = E2{0, 0}

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) MulByFp2(api frontend.API, e1 E6, e2 E2) *E6 {
	res := E6{}

	res.B0.Mul(api, e1.B0, e2)
	res.B1.Mul(api, e1.B1, e2)
	res.B2.Mul(api, e1.B2, e2)

	e.B0 = res.B0
	e.B1 = res.B1
	e.B2 = res.B2

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F²)
func (e *E6) MulByNonResidue(api frontend.API, e1 E6) *E6 {
	res := E6{}
	res.B0.MulByNonResidue(api, e1.B2)
	e.B1 = e1.B0
	e.B2 = e1.B1
	e.B0 = res.B0
	return e
}

// Square sets z to the E6 product of x,x, returns e
func (e *E6) Square(api frontend.API, x E6) *E6 {

	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c4, c5, c1, c2, c3, c0 E2
	c4.Mul(api, x.B0, x.B1).Double(api, c4)
	c5.Square(api, x.B2)
	c1.MulByNonResidue(api, c5).Add(api, c1, c4)
	c2.Sub(api, c4, c5)
	c3.Square(api, x.B0)
	c4.Sub(api, x.B0, x.B1).Add(api, c4, x.B2)
	c5.Mul(api, x.B1, x.B2).Double(api, c5)
	c4.Square(api, c4)
	c0.MulByNonResidue(api, c5).Add(api, c0, c3)
	e.B2.Add(api, c2, c4).Add(api, e.B2, c5).Sub(api, e.B2, c3)
	e.B0 = c0
	e.B1 = c1

	return e
}

// DivUnchecked e6 elmts
func (e *E6) DivUnchecked(api frontend.API, e1, e2 E6) *E6 {

	res, err := api.NewHint(divE6Hint, 6, e1.B0.A0, e1.B0.A1, e1.B1.A0, e1.B1.A1, e1.B2.A0, e1.B2.A1, e2.B0.A0, e2.B0.A1, e2.B1.A0, e2.B1.A1, e2.B2.A0, e2.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E6
	e3.assign(res[:6])
	one.SetOne()

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:6])

	return e
}

// Inverse e6 elmts
func (e *E6) Inverse(api frontend.API, e1 E6) *E6 {

	res, err := api.NewHint(inverseE6Hint, 6, e1.B0.A0, e1.B0.A1, e1.B1.A0, e1.B1.A1, e1.B2.A0, e1.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E6
	e3.assign(res[:6])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:6])

	return e
}

// Assign a value to self (witness assignment)
func (e *E6) Assign(a *bls12377.E6) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
	e.B2.Assign(&a.B2)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E6) AssertIsEqual(api frontend.API, other E6) {
	e.B0.AssertIsEqual(api, other.B0)
	e.B1.AssertIsEqual(api, other.B1)
	e.B2.AssertIsEqual(api, other.B2)
}

// MulByE2 multiplies an element in E6 by an element in E2
func (e *E6) MulByE2(api frontend.API, e1 E6, e2 E2) *E6 {
	e.B0.Mul(api, e1.B0, e2)
	e.B1.Mul(api, e1.B1, e2)
	e.B2.Mul(api, e1.B2, e2)
	return e
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e *E6) MulBy01(api frontend.API, c0, c1 E2) *E6 {

	var a, b, tmp, t0, t1, t2 E2

	a.Mul(api, e.B0, c0)
	b.Mul(api, e.B1, c1)

	tmp.Add(api, e.B1, e.B2)
	t0.Mul(api, c1, tmp)
	t0.Sub(api, t0, b)
	t0.MulByNonResidue(api, t0)
	t0.Add(api, t0, a)

	// for t2, schoolbook is faster than karatsuba
	// c2 = a0b2 + a1b1 + a2b0,
	// c2 = a2b0 + b ∵ b2 = 0, b = a1b1
	t2.Mul(api, e.B2, c0)
	t2.Add(api, t2, b)

	t1.Add(api, c0, c1)
	tmp.Add(api, e.B0, e.B1)
	t1.Mul(api, t1, tmp)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	e.B0 = t0
	e.B1 = t1
	e.B2 = t2

	return e
}

func Mul01By01(api frontend.API, c0, c1, d0, d1 E2) *E6 {
	var a, b, t1, tmp E2

	a.Mul(api, d0, c0)
	b.Mul(api, d1, c1)
	t1.Add(api, c0, c1)
	tmp.Add(api, d0, d1)
	t1.Mul(api, t1, tmp)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	return &E6{
		B0: a,
		B1: t1,
		B2: b,
	}
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E6) Select(api frontend.API, b frontend.Variable, r1, r2 E6) *E6 {

	e.B0.Select(api, b, r1.B0, r2.B0)
	e.B1.Select(api, b, r1.B1, r2.B1)
	e.B2.Select(api, b, r1.B2, r2.B2)

	return e
}
