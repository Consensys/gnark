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

// SetZero returns a newly allocated element equal to 0
func (e *E4) SetZero() *E4 {
	e.B0.SetZero()
	e.B1.SetZero()
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E4) SetOne() *E4 {
	e.B0.SetOne()
	e.B1.SetZero()
	return e
}

// IsZero returns 1 if the element is equal to 0 and 0 otherwise
func (e *E4) IsZero(api frontend.API) frontend.Variable {
	return api.And(e.B0.IsZero(api), e.B1.IsZero(api))
}

func (e *E4) assign(e1 []frontend.Variable) {
	e.B0.A0 = e1[0]
	e.B0.A1 = e1[1]
	e.B1.A0 = e1[2]
	e.B1.A1 = e1[3]
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
func (e *E4) Mul(api frontend.API, e1, e2 E4) *E4 {

	var a, b, c E2

	a.Add(api, e1.B0, e1.B1)
	b.Add(api, e2.B0, e2.B1)
	a.Mul(api, a, b)
	b.Mul(api, e1.B0, e2.B0)
	c.Mul(api, e1.B1, e2.B1)
	e.B1.Sub(api, a, b).Sub(api, e.B1, c)
	e.B0.MulByNonResidue(api, c).Add(api, e.B0, b)

	return e
}

// Square e4 elt
func (e *E4) Square(api frontend.API, x E4) *E4 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf

	var c0, c2, c3 E2

	c0.Sub(api, x.B0, x.B1)
	c3.MulByNonResidue(api, x.B1).Sub(api, x.B0, c3)
	c2.Mul(api, x.B0, x.B1)
	c0.Mul(api, c0, c3).Add(api, c0, c2)
	e.B1.Double(api, c2)
	c2.MulByNonResidue(api, c2)
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
func (e *E4) MulByNonResidue(api frontend.API, e1 E4) *E4 {
	e.B1, e.B0 = e1.B0, e1.B1
	e.B0.MulByNonResidue(api, e.B0)
	return e
}

// Conjugate conjugation of an e4 elmt
func (e *E4) Conjugate(api frontend.API, e1 E4) *E4 {
	e.B0 = e1.B0
	e.B1.Neg(api, e1.B1)
	return e
}

// DivUnchecked e4 elmts
func (e *E4) DivUnchecked(api frontend.API, e1, e2 E4) *E4 {

	res, err := api.NewHint(divE4Hint, 4, e1.B0.A0, e1.B0.A1, e1.B1.A0, e1.B1.A1, e2.B0.A0, e2.B0.A1, e2.B1.A0, e2.B1.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3 E4
	e3.assign(res[:4])

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:4])

	return e
}

// Inverse e4 elmts
func (e *E4) Inverse(api frontend.API, e1 E4) *E4 {

	res, err := api.NewHint(inverseE4Hint, 4, e1.B0.A0, e1.B0.A1, e1.B1.A0, e1.B1.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E4
	e3.assign(res[:4])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:4])

	return e
}

// Assign a value to self (witness assignment)
func (e *E4) Assign(a *bls24315.E4) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E4) AssertIsEqual(api frontend.API, other E4) {
	e.B0.AssertIsEqual(api, other.B0)
	e.B1.AssertIsEqual(api, other.B1)
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E4) Select(api frontend.API, b frontend.Variable, r1, r2 E4) *E4 {

	e.B0.Select(api, b, r1.B0, r2.B0)
	e.B1.Select(api, b, r1.B1, r2.B1)

	return e
}

// Lookup2 implements two-bit lookup. It returns:
//   - r1 if b1=0 and b2=0,
//   - r2 if b1=0 and b2=1,
//   - r3 if b1=1 and b2=0,
//   - r3 if b1=1 and b2=1.
func (e *E4) Lookup2(api frontend.API, b1, b2 frontend.Variable, r1, r2, r3, r4 E4) *E4 {

	e.B0.Lookup2(api, b1, b2, r1.B0, r2.B0, r3.B0, r4.B0)
	e.B1.Lookup2(api, b1, b2, r1.B1, r2.B1, r3.B1, r4.B1)

	return e
}
