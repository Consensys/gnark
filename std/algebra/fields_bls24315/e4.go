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

// E4 element in a quadratic extension
type E4 struct {
	B0, B1 E2
}

// SetOne returns a newly allocated element equal to 1
func (e *E4) SetOne(api frontend.API) *E4 {
	e.B0.A0 = 1
	e.B0.A1 = 0
	e.B1.A0 = 0
	e.B1.A1 = 0
	return e
}

// NewFp4Zero creates a new
func NewFp4Zero(api frontend.API) *E4 {
	return &E4{
		B0: E2{0, 0},
		B1: E2{0, 0},
	}
}

// Neg negates a e4 elmt
func (e *E4) Neg(api frontend.API, e1 E4) *E4 {
	e.B0.Neg(api, e1.B0)
	e.B1.Neg(api, e1.B1)
	return e
}

// Add e4 elmts
func (e *E4) Add(api frontend.API, e1, e2 E4) *E4 {
	e.B0.Add(api, e1.B0, e2.B0)
	e.B1.Add(api, e1.B1, e2.B1)
	return e
}

// Double e4 elmt
func (e *E4) Double(api frontend.API, e1 E4) *E4 {
	e.B0.Double(api, e1.B0)
	e.B1.Double(api, e1.B1)
	return e
}

// Sub e4 elmts
func (e *E4) Sub(api frontend.API, e1, e2 E4) *E4 {
	e.B0.Sub(api, e1.B0, e2.B0)
	e.B1.Sub(api, e1.B1, e2.B1)
	return e
}

// Mul e4 elmts: 5C
func (e *E4) Mul(api frontend.API, e1, e2 E4, ext Extension) *E4 {

	var a, b, c E2

	a.Add(api, e1.B0, e1.B1)
	b.Add(api, e2.B0, e2.B1)
	a.Mul(api, a, b, ext)
	b.Mul(api, e1.B0, e2.B0, ext)
	c.Mul(api, e1.B1, e2.B1, ext)
	e.B1.Sub(api, a, b).Sub(api, e.B1, c)
	e.B0.MulByNonResidue(api, c, ext).Add(api, e.B0, b)

	return e
}

// Square e4 elt
func (e *E4) Square(api frontend.API, x E4, ext Extension) *E4 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf

	var c0, c2, c3 E2

	c0.Sub(api, x.B0, x.B1)
	c3.MulByNonResidue(api, x.B1, ext).Sub(api, x.B0, c3)
	c2.Mul(api, x.B0, x.B1, ext)
	c0.Mul(api, c0, c3, ext).Add(api, c0, c2)
	e.B1.Double(api, c2)
	c2.MulByNonResidue(api, c2, ext)
	e.B0.Add(api, c0, c2)

	return e
}

// MulByFp multiplies an e4 elmt by an fp elmt
func (e *E4) MulByFp(api frontend.API, e1 E4, c interface{}) *E4 {
	e.B0.MulByFp(api, e1.B0, c)
	e.B1.MulByFp(api, e1.B1, c)
	return e
}

// MulByNonResidue multiplies an e4 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E4) MulByNonResidue(api frontend.API, e1 E4, ext Extension) *E4 {
	e.B1, e.B0 = e1.B0, e1.B1
	e.B0.MulByNonResidue(api, e.B0, ext)
	return e
}

// Conjugate conjugation of an e4 elmt
func (e *E4) Conjugate(api frontend.API, e1 E4) *E4 {
	e.B0 = e1.B0
	e.B1.Neg(api, e1.B1)
	return e
}

// Inverse inverses an e4 elmt
func (e *E4) Inverse(api frontend.API, e1 E4, ext Extension) *E4 {

	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	var t0, t1, tmp E2

	t0.Square(api, e1.B0, ext)
	t1.Square(api, e1.B1, ext)
	tmp.MulByNonResidue(api, t1, ext)
	t0.Sub(api, t0, tmp)
	t1.Inverse(api, t0, ext)
	e.B0.Mul(api, e1.B0, t1, ext)
	e.B1.Mul(api, e1.B1, t1, ext).Neg(api, e.B1)

	return e
}

// Assign a value to self (witness assignment)
func (e *E4) Assign(a *bls24315.E4) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E4) MustBeEqual(api frontend.API, other E4) {
	e.B0.MustBeEqual(api, other.B0)
	e.B1.MustBeEqual(api, other.B1)
}
