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
	c0.Mul(api, c0, tmp).Sub(api, c0, t1).Sub(api, c0, t2).MulByNonResidue(api, c0).Add(api, c0, t0)

	c1.Add(api, e1.B0, e1.B1)
	tmp.Add(api, e2.B0, e2.B1)
	c1.Mul(api, c1, tmp).Sub(api, c1, t0).Sub(api, c1, t1)
	tmp.MulByNonResidue(api, t2)
	c1.Add(api, c1, tmp)

	tmp.Add(api, e1.B0, e1.B2)
	c2.Add(api, e2.B0, e2.B2).Mul(api, c2, tmp).Sub(api, c2, t0).Sub(api, c2, t2).Add(api, c2, t1)

	e.B0 = c0
	e.B1 = c1
	e.B2 = c2

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

// Inverse inverses an Fp6 elmt
func (e *E6) Inverse(api frontend.API, e1 E6) *E6 {

	var t [7]E2
	var c [3]E2
	var buf E2

	t[0].Square(api, e1.B0)
	t[1].Square(api, e1.B1)
	t[2].Square(api, e1.B2)
	t[3].Mul(api, e1.B0, e1.B1)
	t[4].Mul(api, e1.B0, e1.B2)
	t[5].Mul(api, e1.B1, e1.B2)

	c[0].MulByNonResidue(api, t[5])

	c[0].Neg(api, c[0]).Add(api, c[0], t[0])

	c[1].MulByNonResidue(api, t[2])

	c[1].Sub(api, c[1], t[3])
	c[2].Sub(api, t[1], t[4])
	t[6].Mul(api, e1.B2, c[1])
	buf.Mul(api, e1.B1, c[2])
	t[6].Add(api, t[6], buf)

	t[6].MulByNonResidue(api, t[6])

	buf.Mul(api, e1.B0, c[0])
	t[6].Add(api, t[6], buf)

	t[6].Inverse(api, t[6])
	e.B0.Mul(api, c[0], t[6])
	e.B1.Mul(api, c[1], t[6])
	e.B2.Mul(api, c[2], t[6])

	return e

}

// Assign a value to self (witness assignment)
func (e *E6) Assign(a *bls12377.E6) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
	e.B2.Assign(&a.B2)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E6) MustBeEqual(api frontend.API, other E6) {
	e.B0.MustBeEqual(api, other.B0)
	e.B1.MustBeEqual(api, other.B1)
	e.B2.MustBeEqual(api, other.B2)
}

// MulByE2 multiplies an element in E6 by an element in E2
func (e *E6) MulByE2(api frontend.API, e1 E6, e2 E2) *E6 {
	e2Copy := E2{}
	e2Copy = e2
	e.B0.Mul(api, e1.B0, e2Copy)
	e.B1.Mul(api, e1.B1, e2Copy)
	e.B2.Mul(api, e1.B2, e2Copy)
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

	tmp.Add(api, e.B0, e.B2)
	t2.Mul(api, c0, tmp)
	t2.Sub(api, t2, a)
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
