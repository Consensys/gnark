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
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

// E2 element in a quadratic extension
type E2 struct {
	A0, A1 frontend.Variable
}

// Neg negates a e2 elmt
func (e *E2) Neg(cs *frontend.ConstraintSystem, e1 *E2) *E2 {
	e.A0 = cs.Sub(0, e1.A0)
	e.A1 = cs.Sub(0, e1.A1)
	return e
}

// Add e2 elmts
func (e *E2) Add(cs *frontend.ConstraintSystem, e1, e2 *E2) *E2 {
	e.A0 = cs.Add(e1.A0, e2.A0)
	e.A1 = cs.Add(e1.A1, e2.A1)
	return e
}

// Sub e2 elmts
func (e *E2) Sub(cs *frontend.ConstraintSystem, e1, e2 *E2) *E2 {
	e.A0 = cs.Sub(e1.A0, e2.A0)
	e.A1 = cs.Sub(e1.A1, e2.A1)
	return e
}

// Mul e2 elmts: 5C
func (e *E2) Mul(cs *frontend.ConstraintSystem, e1, e2 *E2, ext Extension) *E2 {

	// 1C
	l1 := cs.Add(e1.A0, e1.A1)
	l2 := cs.Add(e2.A0, e2.A1)

	u := cs.Mul(l1, l2)

	// 2C
	ac := cs.Mul(e1.A0, e2.A0)
	bd := cs.Mul(e1.A1, e2.A1)

	// 1C
	l31 := cs.Add(ac, bd)
	l3 := cs.Sub(u, l31)

	e.A1 = cs.Mul(l3, 1)

	// 1C
	buSquare := frontend.FromInterface(ext.uSquare)
	l41 := cs.Mul(bd, buSquare)
	l4 := cs.Add(ac, l41)
	e.A0 = cs.Mul(l4, 1)

	return e
}

// Square e2 elt
func (z *E2) Square(cs *frontend.ConstraintSystem, x *E2, ext Extension) *E2 {
	//algo 22 https://eprint.iacr.org/2010/354.pdf
	c0 := cs.Add(x.A0, x.A1)
	buSquare := frontend.FromInterface(ext.uSquare)
	c2 := cs.Mul(x.A1, buSquare)
	c2 = cs.Add(c2, x.A0)

	c0 = cs.Mul(c0, c2) // (x1+x2)*(x1+(u**2)x2)
	c2 = cs.Mul(x.A0, x.A1)
	c2 = cs.Add(c2, c2)
	z.A1 = c2
	c2 = cs.Add(c2, c2)
	z.A0 = cs.Add(c0, c2)

	return z
}

// MulByFp multiplies an fp2 elmt by an fp elmt
func (e *E2) MulByFp(cs *frontend.ConstraintSystem, e1 *E2, c interface{}) *E2 {
	e.A0 = cs.Mul(e1.A0, c)
	e.A1 = cs.Mul(e1.A1, c)
	return e
}

// MulByIm multiplies an fp2 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E2) MulByIm(cs *frontend.ConstraintSystem, e1 *E2, ext Extension) *E2 {
	x := e1.A0
	e.A0 = cs.Mul(e1.A1, ext.uSquare)
	e.A1 = x
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *E2) Conjugate(cs *frontend.ConstraintSystem, e1 *E2) *E2 {
	e.A0 = e1.A0
	e.A1 = cs.Sub(0, e1.A1)
	return e
}

// Inverse inverses an fp2elmt
func (e *E2) Inverse(cs *frontend.ConstraintSystem, e1 *E2, ext Extension) *E2 {

	var a0, a1, t0, t1, t1beta frontend.Variable

	a0 = e1.A0
	a1 = e1.A1

	t0 = cs.Mul(e1.A0, e1.A0)
	t1 = cs.Mul(e1.A1, e1.A1)

	t1beta = cs.Mul(t1, ext.uSquare)
	t0 = cs.Sub(t0, t1beta)
	t1 = cs.Inverse(t0)
	e.A0 = cs.Mul(a0, t1)
	e.A1 = cs.Sub(0, a1)
	e.A1 = cs.Mul(e.A1, t1)

	return e
}

// Assign a value to self (witness assignment)
func (e *E2) Assign(a *bls12377.E2) {
	e.A0.Assign(bls12377FpTobw6761fr(&a.A0))
	e.A1.Assign(bls12377FpTobw6761fr(&a.A1))
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E2) MustBeEqual(cs *frontend.ConstraintSystem, other E2) {
	cs.AssertIsEqual(e.A0, other.A0)
	cs.AssertIsEqual(e.A1, other.A1)
}

func bls12377FpTobw6761fr(a *fp.Element) (r fr.Element) {
	for i, v := range a {
		r[i] = v
	}
	return
}
