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
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

// E2 element in a quadratic extension
type E2 struct {
	A0, A1 frontend.Variable
}

// SetOne returns a newly allocated element equal to 1
func (e *E2) SetOne(api frontend.API) *E2 {
	e.A0 = 1
	e.A1 = 0
	return e
}

// Neg negates a e2 elmt
func (e *E2) Neg(api frontend.API, e1 E2) *E2 {
	e.A0 = api.Sub(0, e1.A0)
	e.A1 = api.Sub(0, e1.A1)
	return e
}

// Add e2 elmts
func (e *E2) Add(api frontend.API, e1, e2 E2) *E2 {
	e.A0 = api.Add(e1.A0, e2.A0)
	e.A1 = api.Add(e1.A1, e2.A1)
	return e
}

// Double e2 elmt
func (e *E2) Double(api frontend.API, e1 E2) *E2 {
	e.A0 = api.Add(e1.A0, e1.A0)
	e.A1 = api.Add(e1.A1, e1.A1)
	return e
}

// Sub e2 elmts
func (e *E2) Sub(api frontend.API, e1, e2 E2) *E2 {
	e.A0 = api.Sub(e1.A0, e2.A0)
	e.A1 = api.Sub(e1.A1, e2.A1)
	return e
}

// Mul e2 elmts: 5C
func (e *E2) Mul(api frontend.API, e1, e2 E2, ext Extension) *E2 {

	// 1C
	l1 := api.Add(e1.A0, e1.A1)
	l2 := api.Add(e2.A0, e2.A1)

	u := api.Mul(l1, l2)

	// 2C
	ac := api.Mul(e1.A0, e2.A0)
	bd := api.Mul(e1.A1, e2.A1)

	// 1C
	l31 := api.Add(ac, bd)
	e.A1 = api.Sub(u, l31)

	// 1C
	buSquare := frontend.FromInterface(ext.uSquare)
	l41 := api.Mul(bd, buSquare)
	e.A0 = api.Add(ac, l41)

	return e
}

// Square e2 elt
func (e *E2) Square(api frontend.API, x E2, ext Extension) *E2 {
	//algo 22 https://eprint.iacr.org/2010/354.pdf
	c0 := api.Add(x.A0, x.A1)
	buSquare := frontend.FromInterface(ext.uSquare)
	c2 := api.Mul(x.A1, buSquare)
	c2 = api.Add(c2, x.A0)

	c0 = api.Mul(c0, c2) // (x1+x2)*(x1+(u**2)x2)
	c2 = api.Mul(x.A0, x.A1)
	c2 = api.Add(c2, c2)
	e.A1 = c2
	c2 = api.Add(c2, c2)
	e.A0 = api.Add(c0, c2)

	return e
}

// MulByFp multiplies an fp2 elmt by an fp elmt
func (e *E2) MulByFp(api frontend.API, e1 E2, c interface{}) *E2 {
	e.A0 = api.Mul(e1.A0, c)
	e.A1 = api.Mul(e1.A1, c)
	return e
}

// MulByNonResidue multiplies an fp2 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E2) MulByNonResidue(api frontend.API, e1 E2, ext Extension) *E2 {
	x := e1.A0
	e.A0 = api.Mul(e1.A1, ext.uSquare)
	e.A1 = x
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *E2) Conjugate(api frontend.API, e1 E2) *E2 {
	e.A0 = e1.A0
	e.A1 = api.Sub(0, e1.A1)
	return e
}

// Inverse inverses an fp2elmt
func (e *E2) Inverse(api frontend.API, e1 E2, ext Extension) *E2 {

	var a0, a1, t0, t1, t1beta frontend.Variable

	a0 = e1.A0
	a1 = e1.A1

	t0 = api.Mul(e1.A0, e1.A0)
	t1 = api.Mul(e1.A1, e1.A1)

	t1beta = api.Mul(t1, ext.uSquare)
	t0 = api.Sub(t0, t1beta)
	e.A0 = api.DivUnchecked(a0, t0)
	e.A1 = api.DivUnchecked(a1, t0)
	e.A1 = api.Sub(0, e.A1)

	return e
}

// Assign a value to self (witness assignment)
func (e *E2) Assign(a *bls12377.E2) {
	e.A0 = (fr.Element)(a.A0)
	e.A1 = (fr.Element)(a.A1)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E2) MustBeEqual(api frontend.API, other E2) {
	api.AssertIsEqual(e.A0, other.A0)
	api.AssertIsEqual(e.A1, other.A1)
}
