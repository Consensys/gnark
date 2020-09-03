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
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/bls377"
	"github.com/consensys/gurvy/bls377/fp"
	"github.com/consensys/gurvy/bw761/fr"
)

// E2 element in a quadratic extension
type E2 struct {
	A0, A1 frontend.Variable
}

func bls377FpTobw761fr(a *fp.Element) (r fr.Element) {
	for i, v := range a {
		r[i] = v
	}
	return
}

func (e *E2) Assign(a *bls377.E2) {
	e.A0.Assign(bls377FpTobw761fr(&a.A0))
	e.A1.Assign(bls377FpTobw761fr(&a.A1))
}

func (e *E2) MUSTBE_EQ(cs *frontend.CS, other E2) {
	cs.MUSTBE_EQ(e.A0, other.A0)
	cs.MUSTBE_EQ(e.A1, other.A1)
}

// Neg negates a e2 elmt
func (e *E2) Neg(cs *frontend.CS, e1 *E2) *E2 {
	e.A0 = cs.SUB(0, e1.A0)
	e.A1 = cs.SUB(0, e1.A1)
	return e
}

// Add e2 elmts
func (e *E2) Add(cs *frontend.CS, e1, e2 *E2) *E2 {
	x := cs.ADD(e1.A0, e2.A0)
	y := cs.ADD(e1.A1, e2.A1)
	e.A0 = x
	e.A1 = y
	return e
}

// Sub e2 elmts
func (e *E2) Sub(cs *frontend.CS, e1, e2 *E2) *E2 {
	x := cs.SUB(e1.A0, e2.A0)
	y := cs.SUB(e1.A1, e2.A1)
	e.A0 = x
	e.A1 = y
	return e
}

// Mul e2 elmts: 5C
func (e *E2) Mul(cs *frontend.CS, e1, e2 *E2, ext Extension) *E2 {

	var one, minusOne big.Int
	one.SetUint64(1)
	minusOne.Neg(&one)

	// 1C
	l1 := frontend.LinearCombination{
		frontend.Term{Variable: e1.A0, Coeff: one},
		frontend.Term{Variable: e1.A1, Coeff: one},
	}
	l2 := frontend.LinearCombination{
		frontend.Term{Variable: e2.A0, Coeff: one},
		frontend.Term{Variable: e2.A1, Coeff: one},
	}
	u := cs.MUL(l1, l2)

	// 2C
	ac := cs.MUL(e1.A0, e2.A0)
	bd := cs.MUL(e1.A1, e2.A1)

	// 1C
	l3 := frontend.LinearCombination{
		frontend.Term{Variable: u, Coeff: one},
		frontend.Term{Variable: ac, Coeff: minusOne},
		frontend.Term{Variable: bd, Coeff: minusOne},
	}
	e.A1 = cs.MUL(l3, 1)

	// 1C
	l4 := frontend.LinearCombination{
		frontend.Term{Variable: ac, Coeff: one},
		frontend.Term{Variable: bd, Coeff: backend.FromInterface(ext.uSquare)},
	}
	e.A0 = cs.MUL(l4, 1)

	return e
}

// MulByFp multiplies an fp2 elmt by an fp elmt
func (e *E2) MulByFp(cs *frontend.CS, e1 *E2, c interface{}) *E2 {
	e.A0 = cs.MUL(e1.A0, c)
	e.A1 = cs.MUL(e1.A1, c)
	return e
}

// MulByIm multiplies an fp2 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E2) MulByIm(cs *frontend.CS, e1 *E2, ext Extension) *E2 {
	x := e1.A0
	e.A0 = cs.MUL(e1.A1, ext.uSquare)
	e.A1 = x
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *E2) Conjugate(cs *frontend.CS, e1 *E2) *E2 {
	e.A0 = e1.A0
	e.A1 = cs.SUB(0, e1.A1)
	return e
}

// Inverse inverses an fp2elmt
func (e *E2) Inverse(cs *frontend.CS, e1 *E2, ext Extension) *E2 {

	var a0, a1, t0, t1, t1beta frontend.Variable

	a0 = e1.A0
	a1 = e1.A1

	t0 = cs.MUL(e1.A0, e1.A0)
	t1 = cs.MUL(e1.A1, e1.A1)

	t1beta = cs.MUL(t1, ext.uSquare)
	t0 = cs.SUB(t0, t1beta)
	t1 = cs.INV(t0)
	e.A0 = cs.MUL(a0, t1)
	e.A1 = cs.SUB(0, a1)
	e.A1 = cs.MUL(e.A1, t1)

	return e
}
