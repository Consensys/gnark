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
func (e *E6) Add(api frontend.API, e1, e2 E6) *E6 {

	e.B0.Add(api, e1.B0, e2.B0)
	e.B1.Add(api, e1.B1, e2.B1)
	e.B2.Add(api, e1.B2, e2.B2)

	return e
}

// NewFp6Zero creates a new
func NewFp6Zero(api frontend.API) *E6 {
	return &E6{
		B0: E2{api.Constant(0), api.Constant(0)},
		B1: E2{api.Constant(0), api.Constant(0)},
		B2: E2{api.Constant(0), api.Constant(0)},
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
func (e *E6) Mul(api frontend.API, e1, e2 E6, ext Extension) *E6 {

	// notations: (a+bv+cv2)*(d+ev+fe2)
	var ad, bf, ce E2
	ad.Mul(api, e1.B0, e2.B0, ext)                       // 5C
	bf.Mul(api, e1.B1, e2.B2, ext).MulByIm(api, bf, ext) // 6C
	ce.Mul(api, e1.B2, e2.B1, ext).MulByIm(api, ce, ext) // 6C

	var cf, ae, bd E2
	cf.Mul(api, e1.B2, e2.B2, ext).MulByIm(api, cf, ext) // 6C
	ae.Mul(api, e1.B0, e2.B1, ext)                       // 5C
	bd.Mul(api, e1.B1, e2.B0, ext)                       // 5C

	var af, be, cd E2
	af.Mul(api, e1.B0, e2.B2, ext) // 5C
	be.Mul(api, e1.B1, e2.B1, ext) // 5C
	cd.Mul(api, e1.B2, e2.B0, ext) // 5C

	e.B0.Add(api, ad, bf).Add(api, e.B0, ce) // 4C
	e.B1.Add(api, cf, ae).Add(api, e.B1, bd) // 4C
	e.B2.Add(api, af, be).Add(api, e.B2, cd) // 4C

	return e
}

// MulByFp2 creates a fp6elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E6) MulByFp2(api frontend.API, e1 E6, e2 E2, ext Extension) *E6 {
	res := E6{}

	res.B0.Mul(api, e1.B0, e2, ext)
	res.B1.Mul(api, e1.B1, e2, ext)
	res.B2.Mul(api, e1.B2, e2, ext)

	e.B0 = res.B0
	e.B1 = res.B1
	e.B2 = res.B2

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F^2)
func (e *E6) MulByNonResidue(api frontend.API, e1 E6, ext Extension) *E6 {
	res := E6{}
	res.B0.Mul(api, e1.B2, ext.vCube, ext)
	e.B1 = e1.B0
	e.B2 = e1.B1
	e.B0 = res.B0
	return e
}

// Inverse inverses an Fp2 elmt
func (e *E6) Inverse(api frontend.API, e1 E6, ext Extension) *E6 {

	var t [7]E2
	var c [3]E2
	var buf E2

	t[0].Mul(api, e1.B0, e1.B0, ext)
	t[1].Mul(api, e1.B1, e1.B1, ext)
	t[2].Mul(api, e1.B2, e1.B2, ext)
	t[3].Mul(api, e1.B0, e1.B1, ext)
	t[4].Mul(api, e1.B0, e1.B2, ext)
	t[5].Mul(api, e1.B1, e1.B2, ext)

	c[0].MulByIm(api, t[5], ext)

	c[0].Neg(api, c[0]).Add(api, c[0], t[0])

	c[1].MulByIm(api, t[2], ext)

	c[1].Sub(api, c[1], t[3])
	c[2].Sub(api, t[1], t[4])
	t[6].Mul(api, e1.B2, c[1], ext)
	buf.Mul(api, e1.B1, c[2], ext)
	t[6].Add(api, t[6], buf)

	t[6].MulByIm(api, t[6], ext)

	buf.Mul(api, e1.B0, c[0], ext)
	t[6].Add(api, t[6], buf)

	t[6].Inverse(api, t[6], ext)
	e.B0.Mul(api, c[0], t[6], ext)
	e.B1.Mul(api, c[1], t[6], ext)
	e.B2.Mul(api, c[2], t[6], ext)

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
