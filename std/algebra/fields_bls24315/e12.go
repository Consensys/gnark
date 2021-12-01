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

package fields_bls24315

import (
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
)

// E12 element in a quadratic extension
type E12 struct {
	C0, C1, C2 E4
}

// Add creates a fp12elmt from fp elmts
func (e *E12) Add(api frontend.API, e1, e2 E12) *E12 {

	e.C0.Add(api, e1.C0, e2.C0)
	e.C1.Add(api, e1.C1, e2.C1)
	e.C2.Add(api, e1.C2, e2.C2)

	return e
}

// NewFp12Zero creates a new
func NewFp12Zero(api frontend.API) *E12 {
	var z E12
	z.C0 = *NewFp4Zero(api)
	z.C1 = *NewFp4Zero(api)
	z.C2 = *NewFp4Zero(api)
	return &z
}

// Sub creates a fp12elmt from fp elmts
func (e *E12) Sub(api frontend.API, e1, e2 E12) *E12 {

	e.C0.Sub(api, e1.C0, e2.C0)
	e.C1.Sub(api, e1.C1, e2.C1)
	e.C2.Sub(api, e1.C2, e2.C2)

	return e
}

// Neg negates an Fp12 elmt
func (e *E12) Neg(api frontend.API, e1 E12) *E12 {
	e.C0.Neg(api, e1.C0)
	e.C1.Neg(api, e1.C1)
	e.C2.Neg(api, e1.C2)
	return e
}

// Mul creates a fp12elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E12) Mul(api frontend.API, e1, e2 E12, ext Extension) *E12 {

	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var t0, t1, t2, c0, c1, c2, tmp E4
	t0.Mul(api, e1.C0, e2.C0, ext)
	t1.Mul(api, e1.C1, e2.C1, ext)
	t2.Mul(api, e1.C2, e2.C2, ext)

	c0.Add(api, e1.C1, e1.C2)
	tmp.Add(api, e2.C1, e2.C2)
	c0.Mul(api, c0, tmp, ext).Sub(api, c0, t1).Sub(api, c0, t2).MulByNonResidue(api, c0, ext).Add(api, c0, t0)

	c1.Add(api, e1.C0, e1.C1)
	tmp.Add(api, e2.C0, e2.C1)
	c1.Mul(api, c1, tmp, ext).Sub(api, c1, t0).Sub(api, c1, t1)
	tmp.MulByNonResidue(api, t2, ext)
	c1.Add(api, c1, tmp)

	tmp.Add(api, e1.C0, e1.C2)
	c2.Add(api, e2.C0, e2.C2).Mul(api, c2, tmp, ext).Sub(api, c2, t0).Sub(api, c2, t2).Add(api, c2, t1)

	e.C0 = c0
	e.C1 = c1
	e.C2 = c2

	return e
}

// MulByFp2 creates a fp12elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E12) MulByFp2(api frontend.API, e1 E12, e2 E4, ext Extension) *E12 {
	res := E12{}

	res.C0.Mul(api, e1.C0, e2, ext)
	res.C1.Mul(api, e1.C1, e2, ext)
	res.C2.Mul(api, e1.C2, e2, ext)

	e.C0 = res.C0
	e.C1 = res.C1
	e.C2 = res.C2

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp12 (noted a+bV+cV where V**3 in F^2)
func (e *E12) MulByNonResidue(api frontend.API, e1 E12, ext Extension) *E12 {
	res := E12{}
	res.C0.MulByNonResidue(api, e1.C2, ext)
	e.C1 = e1.C0
	e.C2 = e1.C1
	e.C0 = res.C0
	return e
}

// Square sets z to the E12 product of x,x, returns e
func (e *E12) Square(api frontend.API, x E12, ext Extension) *E12 {

	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c4, c5, c1, c2, c3, c0 E4
	c4.Mul(api, x.C0, x.C1, ext).Double(api, c4)
	c5.Square(api, x.C2, ext)
	c1.MulByNonResidue(api, c5, ext).Add(api, c1, c4)
	c2.Sub(api, c4, c5)
	c3.Square(api, x.C0, ext)
	c4.Sub(api, x.C0, x.C1).Add(api, c4, x.C2)
	c5.Mul(api, x.C1, x.C2, ext).Double(api, c5)
	c4.Square(api, c4, ext)
	c0.MulByNonResidue(api, c5, ext).Add(api, c0, c3)
	e.C2.Add(api, c2, c4).Add(api, e.C2, c5).Sub(api, e.C2, c3)
	e.C0 = c0
	e.C1 = c1

	return e
}

// Inverse inverses an Fp12 elmt
func (e *E12) Inverse(api frontend.API, e1 E12, ext Extension) *E12 {

	var t [7]E4
	var c [3]E4
	var buf E4

	t[0].Square(api, e1.C0, ext)
	t[1].Square(api, e1.C1, ext)
	t[2].Square(api, e1.C2, ext)
	t[3].Mul(api, e1.C0, e1.C1, ext)
	t[4].Mul(api, e1.C0, e1.C2, ext)
	t[5].Mul(api, e1.C1, e1.C2, ext)

	c[0].MulByNonResidue(api, t[5], ext)

	c[0].Neg(api, c[0]).Add(api, c[0], t[0])

	c[1].MulByNonResidue(api, t[2], ext)

	c[1].Sub(api, c[1], t[3])
	c[2].Sub(api, t[1], t[4])
	t[6].Mul(api, e1.C2, c[1], ext)
	buf.Mul(api, e1.C1, c[2], ext)
	t[6].Add(api, t[6], buf)

	t[6].MulByNonResidue(api, t[6], ext)

	buf.Mul(api, e1.C0, c[0], ext)
	t[6].Add(api, t[6], buf)

	t[6].Inverse(api, t[6], ext)
	e.C0.Mul(api, c[0], t[6], ext)
	e.C1.Mul(api, c[1], t[6], ext)
	e.C2.Mul(api, c[2], t[6], ext)

	return e

}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E12) MustBeEqual(api frontend.API, other E12) {
	e.C0.MustBeEqual(api, other.C0)
	e.C1.MustBeEqual(api, other.C1)
	e.C2.MustBeEqual(api, other.C2)
}

// MulByE4 multiplies an element in E12 by an element in E4
func (e *E12) MulByE4(api frontend.API, e1 E12, e2 E4, ext Extension) *E12 {
	e2Copy := E4{}
	e2Copy = e2
	e.C0.Mul(api, e1.C0, e2Copy, ext)
	e.C1.Mul(api, e1.C1, e2Copy, ext)
	e.C2.Mul(api, e1.C2, e2Copy, ext)
	return e
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e *E12) MulBy01(api frontend.API, c0, c1 E4, ext Extension) *E12 {

	var a, b, tmp, t0, t1, t2 E4

	a.Mul(api, e.C0, c0, ext)
	b.Mul(api, e.C1, c1, ext)

	tmp.Add(api, e.C1, e.C2)
	t0.Mul(api, c1, tmp, ext)
	t0.Sub(api, t0, b)
	t0.MulByNonResidue(api, t0, ext)
	t0.Add(api, t0, a)

	tmp.Add(api, e.C0, e.C2)
	t2.Mul(api, c0, tmp, ext)
	t2.Sub(api, t2, a)
	t2.Add(api, t2, b)

	t1.Add(api, c0, c1)
	tmp.Add(api, e.C0, e.C1)
	t1.Mul(api, t1, tmp, ext)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	e.C0 = t0
	e.C1 = t1
	e.C2 = t2

	return e
}

// Assign a value to self (witness assignment)
func (e *E12) Assign(a *bls24315.E12) {
	e.C0.Assign(&a.C0)
	e.C1.Assign(&a.C1)
	e.C2.Assign(&a.C2)
}
