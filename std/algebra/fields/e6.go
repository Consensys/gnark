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

package fields

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
)

// E6 element in a quadratic extension
type E6 struct {
	B0, B1, B2 E2
}

// Add creates a fp6elmt from fp elmts
func (e *E6) Add(gnark frontend.API, e1, e2 *E6) *E6 {

	e.B0.Add(gnark, &e1.B0, &e2.B0)
	e.B1.Add(gnark, &e1.B1, &e2.B1)
	e.B2.Add(gnark, &e1.B2, &e2.B2)

	return e
}

// NewFp6Zero creates a new
func NewFp6Zero(gnark frontend.API) E6 {
	return E6{
		B0: E2{gnark.Constant(0), gnark.Constant(0)},
		B1: E2{gnark.Constant(0), gnark.Constant(0)},
		B2: E2{gnark.Constant(0), gnark.Constant(0)},
	}
}

// Sub creates a fp6elmt from fp elmts
func (e *E6) Sub(gnark frontend.API, e1, e2 *E6) *E6 {

	e.B0.Sub(gnark, &e1.B0, &e2.B0)
	e.B1.Sub(gnark, &e1.B1, &e2.B1)
	e.B2.Sub(gnark, &e1.B2, &e2.B2)

	return e
}

// Neg negates an Fp6 elmt
func (e *E6) Neg(gnark frontend.API, e1 *E6) *E6 {
	e.B0.Neg(gnark, &e1.B0)
	e.B1.Neg(gnark, &e1.B1)
	e.B2.Neg(gnark, &e1.B2)
	return e
}

// Mul creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) Mul(gnark frontend.API, e1, e2 *E6, ext Extension) *E6 {

	// notations: (a+bv+cv2)*(d+ev+fe2)
	var ad, bf, ce E2
	ad.Mul(gnark, &e1.B0, &e2.B0, ext)                          // 5C
	bf.Mul(gnark, &e1.B1, &e2.B2, ext).MulByIm(gnark, &bf, ext) // 6C
	ce.Mul(gnark, &e1.B2, &e2.B1, ext).MulByIm(gnark, &ce, ext) // 6C

	var cf, ae, bd E2
	cf.Mul(gnark, &e1.B2, &e2.B2, ext).MulByIm(gnark, &cf, ext) // 6C
	ae.Mul(gnark, &e1.B0, &e2.B1, ext)                          // 5C
	bd.Mul(gnark, &e1.B1, &e2.B0, ext)                          // 5C

	var af, be, cd E2
	af.Mul(gnark, &e1.B0, &e2.B2, ext) // 5C
	be.Mul(gnark, &e1.B1, &e2.B1, ext) // 5C
	cd.Mul(gnark, &e1.B2, &e2.B0, ext) // 5C

	e.B0.Add(gnark, &ad, &bf).Add(gnark, &e.B0, &ce) // 4C
	e.B1.Add(gnark, &cf, &ae).Add(gnark, &e.B1, &bd) // 4C
	e.B2.Add(gnark, &af, &be).Add(gnark, &e.B2, &cd) // 4C

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) MulByFp2(gnark frontend.API, e1 *E6, e2 *E2, ext Extension) *E6 {
	res := E6{}

	res.B0.Mul(gnark, &e1.B0, e2, ext)
	res.B1.Mul(gnark, &e1.B1, e2, ext)
	res.B2.Mul(gnark, &e1.B2, e2, ext)

	e.B0 = res.B0
	e.B1 = res.B1
	e.B2 = res.B2

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F^2)
func (e *E6) MulByNonResidue(gnark frontend.API, e1 *E6, ext Extension) *E6 {
	res := E6{}
	res.B0.Mul(gnark, &e1.B2, ext.vCube, ext)
	e.B1 = e1.B0
	e.B2 = e1.B1
	e.B0 = res.B0
	return e
}

// Inverse inverses an Fp2 elmt
func (e *E6) Inverse(gnark frontend.API, e1 *E6, ext Extension) *E6 {

	var t [7]E2
	var c [3]E2
	var buf E2

	t[0].Mul(gnark, &e1.B0, &e1.B0, ext)
	t[1].Mul(gnark, &e1.B1, &e1.B1, ext)
	t[2].Mul(gnark, &e1.B2, &e1.B2, ext)
	t[3].Mul(gnark, &e1.B0, &e1.B1, ext)
	t[4].Mul(gnark, &e1.B0, &e1.B2, ext)
	t[5].Mul(gnark, &e1.B1, &e1.B2, ext)

	c[0].MulByIm(gnark, &t[5], ext)

	c[0].Neg(gnark, &c[0]).Add(gnark, &c[0], &t[0])

	c[1].MulByIm(gnark, &t[2], ext)

	c[1].Sub(gnark, &c[1], &t[3])
	c[2].Sub(gnark, &t[1], &t[4])
	t[6].Mul(gnark, &e1.B2, &c[1], ext)
	buf.Mul(gnark, &e1.B1, &c[2], ext)
	t[6].Add(gnark, &t[6], &buf)

	t[6].MulByIm(gnark, &t[6], ext)

	buf.Mul(gnark, &e1.B0, &c[0], ext)
	t[6].Add(gnark, &t[6], &buf)

	t[6].Inverse(gnark, &t[6], ext)
	e.B0.Mul(gnark, &c[0], &t[6], ext)
	e.B1.Mul(gnark, &c[1], &t[6], ext)
	e.B2.Mul(gnark, &c[2], &t[6], ext)

	return e

}

// Assign a value to self (witness assignment)
func (e *E6) Assign(a *bls12377.E6) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
	e.B2.Assign(&a.B2)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E6) MustBeEqual(gnark frontend.API, other E6) {
	e.B0.MustBeEqual(gnark, other.B0)
	e.B1.MustBeEqual(gnark, other.B1)
	e.B2.MustBeEqual(gnark, other.B2)
}
