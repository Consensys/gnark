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
	"fmt"
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
	// allocate resulting variable
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
	// allocate resulting variable
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
	// allocate resulting variable
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
	// allocate resulting variable
	res := cs.newInternalVariable()

	// O
	O := r1c.LinearExpression{}
	switch t1 := i1.(type) {
	case r1c.LinearExpression:
		O = make(r1c.LinearExpression, len(t1))
		copy(O, t1)
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
		L = make(r1c.LinearExpression, len(t2))
		copy(L, t2)
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

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

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
	// allocate the resulting variables
	res := make([]Variable, nbBits)
	for i := 0; i < nbBits; i++ {
		res[i] = cs.newInternalVariable()
		cs.AssertIsBoolean(res[i])
	}

	var coeff big.Int

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
	// allocate resulting variable
	res := cs.newInternalVariable()

	var coeff big.Int

	L := make(r1c.LinearExpression, len(b))
	for i := 0; i < len(L); i++ {
		if i == 0 {
			coeff.Set(bOne)
		} else if i == 1 {
			coeff.Set(bTwo)
		} else {
			coeff.Mul(&coeff, bTwo)
		}
		L[i] = cs.Term(b[i], &coeff)
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
	// allocate resulting variable
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

	res := cs.newInternalVariable()

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

	R := r1c.LinearExpression{cs.oneTerm}
	O := r1c.LinearExpression{cs.Term(res, bOne)}

	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
	cs.constraints = append(cs.constraints, constraint)

	return res

}

// AssertIsEqual equalizes bTwo variables
func (cs *ConstraintSystem) AssertIsEqual(i1, i2 interface{}) {
	// encoded as L * R == O
	// set L = i1
	// set R = 1
	// set O = i2

	debugInfo := logEntry{}

	//left
	L := r1c.LinearExpression{}
	switch t1 := i1.(type) {
	case r1c.LinearExpression:
		L = make(r1c.LinearExpression, len(t1))
		copy(L, t1)
		debugInfo.format += "["
		for i := 0; i < len(t1); i++ {
			if i > 0 {
				debugInfo.format += " + "
			}
			c := cs.coeffs[t1[i].CoeffID()]
			debugInfo.format += fmt.Sprintf("(%%s * %s)", c.String())
			debugInfo.toResolve = append(debugInfo.toResolve, t1[i])
		}
		debugInfo.format += "]"
	case Variable:
		_t1 := cs.Term(t1, bOne)
		L = append(L, _t1)
		debugInfo.format = "%s"
		debugInfo.toResolve = append(debugInfo.toResolve, _t1)
	default:
		n1 := backend.FromInterface(t1)
		debugInfo.format = fmt.Sprintf("%s", n1.String())
		L = append(L, cs.Term(cs.oneVariable(), &n1))
	}

	debugInfo.format += " == "

	// O
	O := r1c.LinearExpression{}
	switch t2 := i2.(type) {
	case r1c.LinearExpression:
		O = make(r1c.LinearExpression, len(t2))
		copy(O, t2)
		debugInfo.format += "["
		for i := 0; i < len(t2); i++ {
			if i > 0 {
				debugInfo.format += " + "
			}
			c := cs.coeffs[t2[i].CoeffID()]
			debugInfo.format += fmt.Sprintf("(%%s * %s)", c.String())
			debugInfo.toResolve = append(debugInfo.toResolve, t2[i])
		}
		debugInfo.format += "]"
	case Variable:
		_t2 := cs.Term(t2, bOne)
		O = append(O, _t2)
		debugInfo.format += "%s"
		debugInfo.toResolve = append(debugInfo.toResolve, _t2)
	default:
		n2 := backend.FromInterface(t2)
		debugInfo.format += fmt.Sprintf("%s", n2.String())
		O = append(O, cs.Term(cs.oneVariable(), &n2))
	}

	// right
	R := r1c.LinearExpression{cs.oneTerm}

	// prepare debug info to be displayed in case the constraint is not solved
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		debugInfo.format += "\n" + stack[i]
	}

	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
	cs.addAssertion(constraint, debugInfo)
}

// AssertIsBoolean boolean constrains a variable
func (cs *ConstraintSystem) AssertIsBoolean(a Variable) {

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

	// prepare debug info to be displayed in case the constraint is not solved
	debugInfo := logEntry{
		format:    fmt.Sprintf("%%s == (0 or 1)"),
		toResolve: []r1c.Term{r1c.Pack(a.id, 0, a.visibility)},
	}
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		debugInfo.format += "\n" + stack[i]
	}

	cs.addAssertion(constraint, debugInfo)
	a.isBoolean = true
}

// AssertIsLessOrEqual constrains w to be less or equal than e (taken as lifted Integer values from Fr)
// https://github.com/zcash/zips/blOoutputb/master/protocol/protocol.pdf
func (cs *ConstraintSystem) AssertIsLessOrEqual(w Variable, bound interface{}) {

	switch b := bound.(type) {
	case Variable:
		cs.mustBeLessOrEqVar(w, b)
	default:
		cs.mustBeLessOrEqCst(w, backend.FromInterface(b))
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqVar(w, bound Variable) {
	// prepare debug info to be displayed in case the constraint is not solved
	debugInfo := logEntry{
		format:    fmt.Sprintf("%%s <= %%s"),
		toResolve: []r1c.Term{r1c.Pack(w.id, 0, w.visibility), r1c.Pack(bound.id, 0, bound.visibility)},
	}
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		debugInfo.format += "\n" + stack[i]
	}

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
		cs.addAssertion(constraint, debugInfo)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqCst(v Variable, bound big.Int) {
	// prepare debug info to be displayed in case the constraint is not solved
	debugInfo := logEntry{
		format:    fmt.Sprintf("%%s <= %s", bound.String()),
		toResolve: []r1c.Term{r1c.Pack(v.id, 0, v.visibility)},
	}
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		debugInfo.format += "\n" + stack[i]
	}

	const nbBits = 256
	const nbWords = 4
	const wordSize = 64

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
				cs.addAssertion(constraint, debugInfo)

			} else {
				p[(i+1)*wordSize-1-j] = cs.Mul(p[(i+1)*wordSize-j], vBits[(i+1)*wordSize-1-j])
			}
		}
	}
}
