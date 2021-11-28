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

// E8 element in a quadratic extension
type E8 struct {
	C0, C1 E4
}

// SetOne returns a newly allocated element equal to 1
func (e *E8) SetOne(api frontend.API) *E8 {
	e.C0.B0.A0 = 1
	e.C0.B0.A1 = 0
	e.C0.B1.A0 = 0
	e.C0.B1.A1 = 0
	e.C1.B0.A0 = 0
	e.C1.B0.A1 = 0
	e.C1.B1.A0 = 0
	e.C1.B1.A1 = 0

	return e
}

// Neg negates a e8 elmt
func (e *E8) Neg(api frontend.API, e1 E8) *E8 {
	e.C0.Neg(api, e1.C0)
	e.C1.Neg(api, e1.C1)
	return e
}

// Add e8 elmts
func (e *E8) Add(api frontend.API, e1, e2 E8) *E8 {
	e.C0.Add(api, e1.C0, e2.C0)
	e.C1.Add(api, e1.C1, e2.C1)
	return e
}

// Double e8 elmt
func (e *E8) Double(api frontend.API, e1 E8) *E8 {
	e.C0.Double(api, e1.C0)
	e.C1.Double(api, e1.C1)
	return e
}

// Sub e8 elmts
func (e *E8) Sub(api frontend.API, e1, e2 E8) *E8 {
	e.C0.Sub(api, e1.C0, e2.C0)
	e.C1.Sub(api, e1.C1, e2.C1)
	return e
}

// Mul e8 elmts: 5C
func (e *E8) Mul(api frontend.API, e1, e2 E8, ext Extension) *E8 {

	var a, b, c E4

	a.Add(api, e1.C0, e1.C1)
	b.Add(api, e2.C0, e2.C1)
	a.Mul(api, a, b, ext)
	b.Mul(api, e1.C0, e2.C0, ext)
	c.Mul(api, e1.C1, e2.C1, ext)
	e.C1.Sub(api, a, b).Sub(api, e.C1, c)
	e.C0.MulByIm(api, c, ext).Add(api, e.C0, b)

	return e
}

// Square e8 elt
func (e *E8) Square(api frontend.API, x E8, ext Extension) *E8 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf

	var c0, c2, c3 E4

	c0.Sub(api, x.C0, x.C1)
	c3.MulByIm(api, x.C1, ext).Sub(api, x.C0, c3)
	c2.Mul(api, x.C0, x.C1, ext)
	c0.Mul(api, c0, c3, ext).Add(api, c0, c2)
	e.C1.Double(api, c2)
	c2.MulByIm(api, c2, ext)
	e.C0.Add(api, c0, c2)

	return e
}

// MulByFp multiplies an e8 elmt by an fp elmt
func (e *E8) MulByFp(api frontend.API, e1 E8, c interface{}) *E8 {
	e.C0.MulByFp(api, e1.C0, c)
	e.C1.MulByFp(api, e1.C1, c)
	return e
}

// MulByIm multiplies an e8 elmt by the imaginary elmt
func (e *E8) MulByIm(api frontend.API, e1 E8, ext Extension) *E8 {
	e.C1, e.C0 = e1.C0, e1.C1
	e.C0.MulByIm(api, e.C0, ext)
	return e
}

// Conjugate conjugation of an e8 elmt
func (e *E8) Conjugate(api frontend.API, e1 E8) *E8 {
	e.C0 = e1.C0
	e.C1.Neg(api, e1.C1)
	return e
}

// Inverse inverses an e8 elmt
func (e *E8) Inverse(api frontend.API, e1 E8, ext Extension) *E8 {

	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	var t0, t1, tmp E4

	t0.Square(api, e1.C0, ext)
	t1.Square(api, e1.C1, ext)
	tmp.MulByIm(api, t1, ext)
	t0.Sub(api, t0, tmp)
	t1.Inverse(api, t0, ext)
	e.C0.Mul(api, e1.C0, t1, ext)
	e.C1.Mul(api, e1.C1, t1, ext).Neg(api, e.C1)

	return e
}

// Assign a value to self (witness assignment)
func (e *E8) Assign(a *bls24315.E8) {
	e.C0.Assign(&a.C0)
	e.C1.Assign(&a.C1)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E8) MustBeEqual(api frontend.API, other E8) {
	e.C0.MustBeEqual(api, other.C0)
	e.C1.MustBeEqual(api, other.C1)
}
