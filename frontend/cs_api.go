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

package frontend

import (
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs/r1c"
)

// NewPublicInput creates a new public input
func (cs *ConstraintSystem) NewPublicInput(name string) Variable {
	idx := len(cs.publicVariables)
	res := Variable{false, backend.Public, idx, nil}

	// checks if the name is not already picked
	for _, v := range cs.publicVariableNames {
		if v == name {
			panic("duplicate input name (public)")
		}
	}

	cs.publicVariableNames = append(cs.publicVariableNames, name)
	cs.publicVariables = append(cs.publicVariables, res)
	return res
}

// NewSecretInput creates a new public input
func (cs *ConstraintSystem) NewSecretInput(name string) Variable {
	idx := len(cs.secretVariables)
	res := Variable{false, backend.Secret, idx, nil}

	// checks if the name is not already picked
	for _, v := range cs.publicVariableNames {
		if v == name {
			panic("duplicate input name (secret)")
		}
	}

	cs.secretVariableNames = append(cs.secretVariableNames, name)
	cs.secretVariables = append(cs.secretVariables, res)
	return res
}

// Add adds 2 wires
func (cs *ConstraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	res := cs.newInternalVariable()

	L := r1c.LinearExpression{}

	add := func(_i interface{}) {
		switch t := _i.(type) {
		case Variable:

			L = append(L, cs.Term(t, bOne))
		default:
			n := backend.FromInterface(t)

			L = append(L, cs.Term(cs.oneVariable(), &n))
		}
	}
	add(i1)
	add(i2)
	for i := 0; i < len(in); i++ {
		add(in[i])
	}

	R := r1c.LinearExpression{
		cs.oneTerm,
	}
	O := r1c.LinearExpression{
		cs.Term(res, bOne),
	}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Sub Adds bTwo wires
func (cs *ConstraintSystem) Sub(i1, i2 interface{}) Variable {

	res := cs.newInternalVariable()

	L := r1c.LinearExpression{}
	switch t := i1.(type) {
	case Variable:

		L = append(L, cs.Term(t, bOne))
	default:
		n := backend.FromInterface(t)

		L = append(L, cs.Term(cs.oneVariable(), &n))
	}

	switch t := i2.(type) {
	case Variable:

		L = append(L, cs.Term(t, bMinusOne))
	default:
		n := backend.FromInterface(t)
		n.Mul(&n, bMinusOne)

		L = append(L, cs.Term(cs.oneVariable(), &n))
	}

	R := r1c.LinearExpression{
		cs.oneTerm,
	}
	O := r1c.LinearExpression{
		cs.Term(res, bOne),
	}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Mul multiplies 2 wires
func (cs *ConstraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {

	mul := func(_i1, _i2 interface{}) Variable {

		_res := cs.newInternalVariable()

		L := r1c.LinearExpression{}
		R := r1c.LinearExpression{}

		// left
		switch t1 := _i1.(type) {
		case r1c.LinearExpression:
			L = make(r1c.LinearExpression, len(t1))
			copy(L, t1)
		case Variable:

			L = append(L, cs.Term(t1, bOne))
		default:
			n1 := backend.FromInterface(t1)

			L = append(L, cs.Term(cs.oneVariable(), &n1))
		}

		// right
		switch t2 := _i2.(type) {
		case r1c.LinearExpression:
			R = make(r1c.LinearExpression, len(t2))
			copy(R, t2)
		case Variable:

			R = append(R, cs.Term(t2, bOne))
		default:
			n2 := backend.FromInterface(t2)

			R = append(R, cs.Term(cs.oneVariable(), &n2))
		}

		O := r1c.LinearExpression{
			cs.Term(_res, bOne),
		}
		constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
		cs.constraints = append(cs.constraints, constraint)
		return _res
	}

	res := mul(i1, i2)
	for i := 0; i < len(in); i++ {
		res = mul(res, in[i])
	}

	return res
}

// Inverse inverses a variable
func (cs *ConstraintSystem) Inverse(v Variable) Variable {

	res := cs.newInternalVariable()

	L := r1c.LinearExpression{cs.Term(res, bOne)}
	R := r1c.LinearExpression{cs.Term(v, bOne)}
	O := r1c.LinearExpression{cs.oneTerm}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Div divides bTwo constraints (i1/i2)
func (cs *ConstraintSystem) Div(i1, i2 interface{}) Variable {

	res := cs.newInternalVariable()

	// O
	O := r1c.LinearExpression{}
	switch t1 := i1.(type) {
	case r1c.LinearExpression:
		O = t1
	case Variable:
		O = append(O, cs.Term(t1, bOne))
	default:
		n1 := backend.FromInterface(t1)
		O = append(O, cs.Term(cs.oneVariable(), &n1))
	}

	// left
	L := r1c.LinearExpression{}
	switch t2 := i2.(type) {
	case r1c.LinearExpression:
		L = t2
	case Variable:
		L = append(L, cs.Term(t2, bOne))
	default:
		n2 := backend.FromInterface(t2)
		L = append(L, cs.Term(cs.oneVariable(), &n2))
	}

	R := r1c.LinearExpression{cs.Term(res, bOne)}

	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Xor compute the xor between bTwo constraints
func (cs *ConstraintSystem) Xor(a, b Variable) Variable {

	cs.MustBeBoolean(a)
	cs.MustBeBoolean(b)

	res := cs.newInternalVariable()
	L := r1c.LinearExpression{
		cs.Term(a, bTwo),
	}
	R := r1c.LinearExpression{
		cs.Term(b, bOne),
	}
	O := r1c.LinearExpression{
		cs.Term(a, bOne),
		cs.Term(b, bOne),
		cs.Term(res, bMinusOne),
	}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res
}

// ToBinary unpacks a variable in binary, n is the number of bits of the variable
// The result in in little endian (first bit= lsb)
func (cs *ConstraintSystem) ToBinary(a Variable, nbBits int) []Variable {

	var coeff big.Int

	// allocate the resulting variables
	res := make([]Variable, nbBits)
	for i := 0; i < nbBits; i++ {
		res[i] = cs.newInternalVariable()
		cs.MustBeBoolean(res[i])
	}

	// add the constraint
	L := make(r1c.LinearExpression, nbBits)
	for i := 0; i < nbBits; i++ {
		if i == 0 {
			coeff.Set(bOne)
		} else if i == 1 {
			coeff.Set(bTwo)
		} else {
			coeff.Mul(&coeff, bTwo)
		}
		L[i] = cs.Term(res[i], &coeff)
	}
	R := r1c.LinearExpression{
		cs.oneTerm,
	}
	O := r1c.LinearExpression{
		cs.Term(a, bOne),
	}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.BinaryDec}

	cs.constraints = append(cs.constraints, constraint)

	return res

}

// FromBinary packs b, seen as a fr.Element in little endian
func (cs *ConstraintSystem) FromBinary(b ...Variable) Variable {

	res := cs.newInternalVariable()

	l := len(b)

	idx := make([]int, l)

	var tmp big.Int
	tmp.Set(bTwo)
	idx[0] = cs.coeffID(bOne)
	idx[1] = cs.coeffID(bTwo)

	for i := 2; i < l; i++ {
		tmp.Mul(&tmp, bTwo)
		idx[i] = cs.coeffID(&tmp)
	}

	L := make(r1c.LinearExpression, l)
	for i := 0; i < l; i++ {
		L[i].SetCoeffID(idx[i])
		L[i].SetConstraintID(b[i].id)
		L[i].SetConstraintVisibility(b[i].visibility)
		// TODO we forgot about boolean variables...
		// L[i].Variable = b[i]
		// L[i].Coeff = idx[i]
	}
	R := r1c.LinearExpression{
		cs.oneTerm,
	}
	O := r1c.LinearExpression{
		cs.Term(res, bOne),
	}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Select if b is true, yields c1 else yields c2
func (cs *ConstraintSystem) Select(b Variable, i1, i2 interface{}) Variable {

	res := cs.newInternalVariable()

	L := r1c.LinearExpression{
		cs.Term(b, bOne),
	}

	// R, first part
	R := r1c.LinearExpression{}
	switch t1 := i1.(type) {
	case r1c.LinearExpression:
		R = make(r1c.LinearExpression, len(t1))
		copy(R, t1)
	case Variable:

		R = append(R, cs.Term(t1, bOne))
	default:
		n1 := backend.FromInterface(t1)
		R = append(R, cs.Term(cs.oneVariable(), &n1))
	}

	// R, second part
	toAppend := r1c.LinearExpression{}
	switch t2 := i2.(type) {
	case r1c.LinearExpression:
		for _, e := range t2 {
			coef := cs.coeffs[e.CoeffID()]
			coef.Mul(&coef, bMinusOne)
			newCoeffID := cs.coeffID(&coef)
			newTerm := e
			newTerm.SetCoeffID(newCoeffID)
			toAppend = append(toAppend, newTerm)
		}
	case Variable:

		toAppend = append(toAppend, cs.Term(t2, bMinusOne))
	default:
		n2 := backend.FromInterface(t2)
		toAppend = append(toAppend, cs.Term(cs.oneVariable(), &n2))
	}
	R = append(R, toAppend...)

	O := r1c.LinearExpression{
		cs.Term(res, bOne),
	}
	O = append(O, toAppend...)

	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Constant will return a Variable from input {uint64, int, ...}
func (cs *ConstraintSystem) Constant(input interface{}) Variable {

	//L
	L := r1c.LinearExpression{}

	switch t := input.(type) {
	case Variable:

		return t
	default:
		n := backend.FromInterface(t)
		if n.Cmp(bOne) == 0 {
			return cs.oneVariable()
		}

		L = append(L, cs.Term(cs.oneVariable(), &n))
	}

	res := cs.newInternalVariable()
	R := r1c.LinearExpression{cs.oneTerm}
	O := r1c.LinearExpression{cs.Term(res, bOne)}

	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.constraints = append(cs.constraints, constraint)

	return res

}

// MustBeEqual equalizes bTwo variables
func (cs *ConstraintSystem) MustBeEqual(i1, i2 interface{}) {

	//left
	L := r1c.LinearExpression{}
	switch t1 := i1.(type) {
	case r1c.LinearExpression:
		L = make(r1c.LinearExpression, len(t1))
		copy(L, t1)
	case Variable:

		L = append(L, cs.Term(t1, bOne))
	default:
		n1 := backend.FromInterface(t1)

		L = append(L, cs.Term(cs.oneVariable(), &n1))
	}

	// O
	O := r1c.LinearExpression{}
	switch t2 := i2.(type) {
	case r1c.LinearExpression:
		O = make(r1c.LinearExpression, len(t2))
		copy(O, t2)
	case Variable:

		O = append(O, cs.Term(t2, bOne))
	default:
		n2 := backend.FromInterface(t2)

		O = append(O, cs.Term(cs.oneVariable(), &n2))
	}

	// right
	R := r1c.LinearExpression{cs.oneTerm}

	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}

	cs.assertions = append(cs.assertions, constraint)
}

// MustBeBoolean boolean constrains a variable
func (cs *ConstraintSystem) MustBeBoolean(a Variable) {

	if a.isBoolean {
		return
	}

	L := r1c.LinearExpression{
		cs.Term(a, bOne),
	}
	R := r1c.LinearExpression{
		cs.oneTerm,
		cs.Term(a, bMinusOne),
	}
	O := r1c.LinearExpression{
		cs.Term(cs.oneVariable(), bZero),
	}
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
	cs.assertions = append(cs.assertions, constraint)
	a.isBoolean = true
}

// MustBeLessOrEqual constrains w to be less or equal than e (taken as lifted Integer values from Fr)
// https://github.com/zcash/zips/blOoutputb/master/protocol/protocol.pdf
func (cs *ConstraintSystem) MustBeLessOrEqual(w Variable, bound interface{}) {

	switch b := bound.(type) {
	case Variable:

		cs.mustBeLessOrEqVar(w, b)
	default:
		_bound := backend.FromInterface(b)
		cs.mustBeLessOrEqCst(w, _bound)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqVar(w, bound Variable) {

	const nbBits = 256

	binw := cs.ToBinary(w, nbBits)
	binbound := cs.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = cs.Constant(1)

	for i := nbBits - 1; i >= 0; i-- {
		p1 := cs.Mul(p[i+1], binw[i])
		p[i] = cs.Select(binbound[i], p1, p[i+1])

		zero := cs.Constant(0)
		t := cs.Select(binbound[i], zero, p[i+1])
		L := r1c.LinearExpression{
			cs.oneTerm,
			cs.Term(t, bMinusOne),
			cs.Term(binw[i], bMinusOne),
		}
		R := r1c.LinearExpression{
			cs.Term(binw[i], bOne),
		}
		O := r1c.LinearExpression{
			cs.Term(cs.oneVariable(), bZero),
		}
		constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
		cs.assertions = append(cs.assertions, constraint)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqCst(v Variable, bound big.Int) {

	nbBits := 256
	nbWords := 4
	wordSize := 64

	vBits := cs.ToBinary(v, nbBits)
	boundBits := bound.Bits()
	l := len(boundBits)
	if len(boundBits) < nbWords {
		for i := 0; i < nbWords-l; i++ {
			boundBits = append(boundBits, big.Word(0))
		}
	}
	p := make([]Variable, nbBits+1)

	p[nbBits] = cs.Constant(1)
	for i := nbWords - 1; i >= 0; i-- {
		for j := 0; j < wordSize; j++ {
			b := (boundBits[i] >> (wordSize - 1 - j)) & 1
			if b == 0 {
				p[(i+1)*wordSize-1-j] = p[(i+1)*wordSize-j]
				L := r1c.LinearExpression{
					cs.oneTerm,
					cs.Term(p[(i+1)*wordSize-j], bMinusOne),
					cs.Term(vBits[(i+1)*wordSize-1-j], bMinusOne),
				}
				R := r1c.LinearExpression{cs.Term(vBits[(i+1)*wordSize-1-j], bOne)}
				O := r1c.LinearExpression{cs.Term(cs.oneVariable(), bZero)}
				constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
				cs.assertions = append(cs.assertions, constraint)

			} else {
				p[(i+1)*wordSize-1-j] = cs.Mul(p[(i+1)*wordSize-j], vBits[(i+1)*wordSize-1-j])
			}
		}
	}
}
