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
	"github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
)

// E2 element in a quadratic extension
type E2 struct {
	A0, A1 frontend.Variable
}

// SetZero returns a newly allocated element equal to 0
func (e *E2) SetZero() *E2 {
	e.A0 = 0
	e.A1 = 0
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E2) SetOne() *E2 {
	e.A0 = 1
	e.A1 = 0
	return e
}

// IsZero returns 1 if the element is equal to 0 and 0 otherwise
func (e *E2) IsZero(api frontend.API) frontend.Variable {
	return api.And(api.IsZero(e.A0), api.IsZero(e.A1))
}

func (e *E2) assign(e1 []frontend.Variable) {
	e.A0 = e1[0]
	e.A1 = e1[1]
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
func (e *E2) Mul(api frontend.API, e1, e2 E2) *E2 {

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
	buSquare := utils.FromInterface(ext.uSquare)
	l41 := api.Mul(bd, buSquare)
	e.A0 = api.Add(ac, l41)

	return e
}

// Square e2 elt
func (e *E2) Square(api frontend.API, x E2) *E2 {
	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf

	c0 := api.Sub(x.A0, x.A1)
	buSquare := utils.FromInterface(ext.uSquare)
	c3 := api.Mul(x.A1, buSquare)
	c3 = api.Sub(x.A0, c3)
	c2 := api.Mul(x.A0, x.A1)
	c0 = api.Mul(c0, c3)
	c0 = api.Add(c0, c2)
	e.A1 = api.Add(c2, c2)
	c2 = api.Mul(c2, buSquare)
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
func (e *E2) MulByNonResidue(api frontend.API, e1 E2) *E2 {
	e.A0, e.A1 = e1.A1, e1.A0
	e.A0 = api.Mul(e.A0, ext.uSquare)
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *E2) Conjugate(api frontend.API, e1 E2) *E2 {
	e.A0 = e1.A0
	e.A1 = api.Sub(0, e1.A1)
	return e
}

// DivUnchecked e2 elmts
func (e *E2) DivUnchecked(api frontend.API, e1, e2 E2) *E2 {

	res, err := api.NewHint(divE2Hint, 2, e1.A0, e1.A1, e2.A0, e2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3 E2
	e3.assign(res[:2])

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:2])

	return e
}

// Inverse e2 elmts
func (e *E2) Inverse(api frontend.API, e1 E2) *E2 {

	res, err := api.NewHint(inverseE2Hint, 2, e1.A0, e1.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E2
	e3.assign(res[:2])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:2])

	return e
}

// Assign a value to self (witness assignment)
func (e *E2) Assign(a *bls24315.E2) {
	e.A0 = (fr.Element)(a.A0)
	e.A1 = (fr.Element)(a.A1)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E2) AssertIsEqual(api frontend.API, other E2) {
	api.AssertIsEqual(e.A0, other.A0)
	api.AssertIsEqual(e.A1, other.A1)
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E2) Select(api frontend.API, b frontend.Variable, r1, r2 E2) *E2 {

	e.A0 = api.Select(b, r1.A0, r2.A0)
	e.A1 = api.Select(b, r1.A1, r2.A1)

	return e
}

// Lookup2 implements two-bit lookup. It returns:
//   - r1 if b1=0 and b2=0,
//   - r2 if b1=0 and b2=1,
//   - r3 if b1=1 and b2=0,
//   - r3 if b1=1 and b2=1.
func (e *E2) Lookup2(api frontend.API, b1, b2 frontend.Variable, r1, r2, r3, r4 E2) *E2 {

	e.A0 = api.Lookup2(b1, b2, r1.A0, r2.A0, r3.A0, r4.A0)
	e.A1 = api.Lookup2(b1, b2, r1.A1, r2.A1, r3.A1, r4.A1)

	return e
}
