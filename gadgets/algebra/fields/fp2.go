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
)

// Fp2Elmt element in a quadratic extension
type Fp2Elmt struct {
	X, Y *frontend.Constraint
}

// NewFp2Zero creates a new
func NewFp2Zero(circuit *frontend.CS) Fp2Elmt {
	return NewFp2Elmt(circuit,
		circuit.ALLOCATE(0),
		circuit.ALLOCATE(0),
	)
}

// NewFp2Elmt creates a fp2elmt from x, y points
func NewFp2Elmt(circuit *frontend.CS, _x, _y interface{}) Fp2Elmt {

	if _x == nil && _y == nil {
		return Fp2Elmt{nil, nil}
	}
	res := Fp2Elmt{
		X: circuit.ALLOCATE(_x),
		Y: circuit.ALLOCATE(_y),
	}
	return res
}

// Neg negates a e2 elmt
func (e *Fp2Elmt) Neg(circuit *frontend.CS, e1 *Fp2Elmt) *Fp2Elmt {
	e.X = circuit.SUB(0, e1.X)
	e.Y = circuit.SUB(0, e1.Y)
	return e
}

// Add e2 elmts
func (e *Fp2Elmt) Add(circuit *frontend.CS, e1, e2 *Fp2Elmt) *Fp2Elmt {
	x := circuit.ADD(e1.X, e2.X)
	y := circuit.ADD(e1.Y, e2.Y)
	e.X = x
	e.Y = y
	return e
}

// Sub e2 elmts
func (e *Fp2Elmt) Sub(circuit *frontend.CS, e1, e2 *Fp2Elmt) *Fp2Elmt {
	x := circuit.SUB(e1.X, e2.X)
	y := circuit.SUB(e1.Y, e2.Y)
	e.X = x
	e.Y = y
	return e
}

// Mul e2 elmts: 5C
func (e *Fp2Elmt) Mul(circuit *frontend.CS, e1, e2 *Fp2Elmt, ext Extension) *Fp2Elmt {

	var one, minusOne big.Int
	one.SetUint64(1)
	minusOne.Neg(&one)

	// 1C
	l1 := frontend.LinearCombination{
		frontend.Term{Constraint: e1.X, Coeff: one},
		frontend.Term{Constraint: e1.Y, Coeff: one},
	}
	l2 := frontend.LinearCombination{
		frontend.Term{Constraint: e2.X, Coeff: one},
		frontend.Term{Constraint: e2.Y, Coeff: one},
	}
	u := circuit.MUL(l1, l2)

	// 2C
	ac := circuit.MUL(e1.X, e2.X)
	bd := circuit.MUL(e1.Y, e2.Y)

	// 1C
	l3 := frontend.LinearCombination{
		frontend.Term{Constraint: u, Coeff: one},
		frontend.Term{Constraint: ac, Coeff: minusOne},
		frontend.Term{Constraint: bd, Coeff: minusOne},
	}
	e.Y = circuit.MUL(l3, 1)

	// 1C
	l4 := frontend.LinearCombination{
		frontend.Term{Constraint: ac, Coeff: one},
		frontend.Term{Constraint: bd, Coeff: backend.FromInterface(ext.uSquare)},
	}
	e.X = circuit.MUL(l4, 1)

	return e
}

// MulByFp multiplies an fp2 elmt by an fp elmt
func (e *Fp2Elmt) MulByFp(circuit *frontend.CS, e1 *Fp2Elmt, c interface{}) *Fp2Elmt {
	e.X = circuit.MUL(e1.X, c)
	e.Y = circuit.MUL(e1.Y, c)
	return e
}

// MulByIm multiplies an fp2 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *Fp2Elmt) MulByIm(circuit *frontend.CS, e1 *Fp2Elmt, ext Extension) *Fp2Elmt {
	x := e1.X
	e.X = circuit.MUL(e1.Y, ext.uSquare)
	e.Y = x
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *Fp2Elmt) Conjugate(circuit *frontend.CS, e1 *Fp2Elmt) *Fp2Elmt {
	e.X = e1.X
	e.Y = circuit.SUB(0, e1.Y)
	return e
}

// Inverse inverses an fp2elmt
func (e *Fp2Elmt) Inverse(circuit *frontend.CS, e1 *Fp2Elmt, ext Extension) *Fp2Elmt {

	var a0, a1, t0, t1, t1beta *frontend.Constraint

	a0 = e1.X
	a1 = e1.Y

	t0 = circuit.MUL(e1.X, e1.X)
	t1 = circuit.MUL(e1.Y, e1.Y)

	t1beta = circuit.MUL(t1, ext.uSquare)
	t0 = circuit.SUB(t0, t1beta)
	t1 = circuit.INV(t0)
	e.X = circuit.MUL(a0, t1)
	e.Y = circuit.SUB(0, a1)
	e.Y = circuit.MUL(e.Y, t1)

	return e
}
