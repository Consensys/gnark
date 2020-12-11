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

// Add returns res = i1+i2+...in
func (cs *ConstraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	var res Variable

	add := func(_i interface{}) {
		switch t := _i.(type) {
		case Variable:
			cs.completeDanglingVariable(&t) // always call this in case of a dangling variable, otherwise compile will not recognize Unset variables
			res.linExp = append(res.linExp, t.getLinExpCopy()...)
		default:
			v := cs.Constant(t)
			res.linExp = append(res.linExp, v.getLinExpCopy()...)
		}
	}
	add(i1)
	add(i2)
	for i := 0; i < len(in); i++ {
		add(in[i])
	}

	res.linExp = cs.reduce(res.linExp)

	return res
}

// returns -le, the result is a copy
func (cs *ConstraintSystem) negateLinExp(le r1c.LinearExpression) r1c.LinearExpression {
	res := make(r1c.LinearExpression, len(le))
	var coeff, coeffCopy big.Int
	for i, t := range le {
		_, coeffID, variableID, constraintVis := t.Unpack()
		coeff = cs.coeffs[coeffID]
		coeffCopy.Neg(&coeff)
		res[i] = cs.makeTerm(PartialVariable{constraintVis, variableID, nil}, &coeffCopy)
	}
	return res
}

// Sub returns res = i1 - i2
func (cs *ConstraintSystem) Sub(i1, i2 interface{}) Variable {

	var res Variable

	switch t := i1.(type) {
	case Variable:
		cs.completeDanglingVariable(&t)
		res.linExp = t.getLinExpCopy()
	default:
		v := cs.Constant(t)
		res.linExp = v.getLinExpCopy()
	}

	switch t := i2.(type) {
	case Variable:
		cs.completeDanglingVariable(&t)
		negLinExp := cs.negateLinExp(t.getLinExpCopy())
		res.linExp = append(res.getLinExpCopy(), negLinExp...)
	default:
		v := cs.Constant(t)
		negLinExp := cs.negateLinExp(v.getLinExpCopy())
		res.linExp = append(res.getLinExpCopy(), negLinExp...)
	}

	res.linExp = cs.reduce(res.linExp)

	return res
}

func (cs *ConstraintSystem) mulConstant(i interface{}, v Variable) Variable {
	var linExp r1c.LinearExpression
	lambda := backend.FromInterface(i)
	for _, t := range v.linExp {
		var coeffCopy big.Int
		_, coeffID, variableID, constraintVis := t.Unpack()
		coeff := cs.coeffs[coeffID]
		coeffCopy.Mul(&coeff, &lambda)
		linExp = append(linExp, cs.makeTerm(PartialVariable{constraintVis, variableID, nil}, &coeffCopy))
	}
	return Variable{PartialVariable{}, linExp, false}
}

// Mul returns res = i1 * i2 * ... in
func (cs *ConstraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {

	mul := func(_i1, _i2 interface{}) Variable {
		var _res Variable
		switch t1 := _i1.(type) {
		case Variable:
			cs.completeDanglingVariable(&t1)
			switch t2 := _i2.(type) {
			case Variable:
				cs.completeDanglingVariable(&t2)
				_res = cs.newInternalVariable() // only in this case we record the constraint in the cs
				constraint := r1c.R1C{L: t1.getLinExpCopy(), R: t2.getLinExpCopy(), O: _res.getLinExpCopy(), Solver: r1c.SingleOutput}
				cs.constraints = append(cs.constraints, constraint)
				return _res
			default:
				_res = cs.mulConstant(t2, t1)
				return _res
			}
		default:
			switch t2 := _i2.(type) {
			case Variable:
				cs.completeDanglingVariable(&t2)
				_res = cs.mulConstant(t1, t2)
				return _res
			default:
				n1 := backend.FromInterface(t1)
				n2 := backend.FromInterface(t2)
				n1.Mul(&n1, &n2)
				_res = cs.Constant(n1)
				return _res
			}
		}
	}

	res := mul(i1, i2)

	for i := 0; i < len(in); i++ {
		res = mul(res, in[i])
	}

	return res
}

// Inverse returns res = inverse(v)
// TODO the function should take an interface
func (cs *ConstraintSystem) Inverse(v Variable) Variable {

	cs.completeDanglingVariable(&v)

	// allocate resulting variable
	res := cs.newInternalVariable()

	L := v.linExp
	R := res.linExp
	O := cs.LinearExpression(cs.getOneTerm())
	constraint := r1c.R1C{L: L, R: R, O: O, Solver: r1c.SingleOutput}
	cs.constraints = append(cs.constraints, constraint)

	return res
}

// Div returns res = i1 / i2
func (cs *ConstraintSystem) Div(i1, i2 interface{}) Variable {

	// allocate resulting variable
	res := cs.newInternalVariable()

	// O
	switch t1 := i1.(type) {
	case Variable:
		cs.completeDanglingVariable(&t1)
		switch t2 := i2.(type) {
		case Variable:
			cs.completeDanglingVariable(&t2)
			constraint := r1c.R1C{L: t2.linExp, R: res.linExp, O: t1.linExp, Solver: r1c.SingleOutput}
			cs.constraints = append(cs.constraints, constraint)
		default:
			tmp := cs.Constant(t2)
			constraint := r1c.R1C{L: tmp.getLinExpCopy(), R: res.getLinExpCopy(), O: t1.getLinExpCopy(), Solver: r1c.SingleOutput}
			cs.constraints = append(cs.constraints, constraint)
		}
	default:
		switch t2 := i2.(type) {
		case Variable:
			cs.completeDanglingVariable(&t2)
			tmp := cs.Constant(t1)
			constraint := r1c.R1C{L: t2.getLinExpCopy(), R: res.getLinExpCopy(), O: tmp.getLinExpCopy(), Solver: r1c.SingleOutput}
			cs.constraints = append(cs.constraints, constraint)
		default:
			tmp1 := cs.Constant(t1)
			tmp2 := cs.Constant(t2)
			constraint := r1c.R1C{L: tmp2.getLinExpCopy(), R: res.getLinExpCopy(), O: tmp1.getLinExpCopy(), Solver: r1c.SingleOutput}
			cs.constraints = append(cs.constraints, constraint)
		}
	}

	return res
}

// Xor compute the xor between two variables
func (cs *ConstraintSystem) Xor(a, b Variable) Variable {

	cs.completeDanglingVariable(&a)
	cs.completeDanglingVariable(&b)

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.newInternalVariable()
	v1 := cs.Mul(2, a)   // no constraint recorded
	v2 := cs.Add(a, b)   // no constraint recorded
	v2 = cs.Sub(v2, res) // no constraint recorded

	constraint := r1c.R1C{L: v1.getLinExpCopy(), R: b.getLinExpCopy(), O: v2.getLinExpCopy(), Solver: r1c.SingleOutput}
	cs.constraints = append(cs.constraints, constraint)

	return res
}

// ToBinary unpacks a variable in binary, n is the number of bits of the variable
//
// The result in in little endian (first bit= lsb)
func (cs *ConstraintSystem) ToBinary(a Variable, nbBits int) []Variable {

	cs.completeDanglingVariable(&a)

	// allocate the resulting variables
	res := make([]Variable, nbBits)
	for i := 0; i < nbBits; i++ {
		res[i] = cs.newInternalVariable()
		cs.AssertIsBoolean(res[i])
	}

	var coeff big.Int
	coeff.Set(bTwo)

	var v, _v Variable
	v = cs.Mul(res[0], 1) // no constraint is recorded

	// add the constraint
	for i := 1; i < nbBits; i++ {
		_v = cs.Mul(coeff, res[i]) // no constraint is recorded
		v = cs.Add(v, _v)          // no constraint is recorded
		coeff.Mul(&coeff, bTwo)
	}

	r := cs.getOneVariable()

	constraint := r1c.R1C{L: v.getLinExpCopy(), R: r.getLinExpCopy(), O: a.getLinExpCopy(), Solver: r1c.BinaryDec}
	cs.constraints = append(cs.constraints, constraint)

	return res

}

// FromBinary packs b, seen as a fr.Element in little endian
func (cs *ConstraintSystem) FromBinary(b ...Variable) Variable {

	for i := 0; i < len(b); i++ {
		cs.completeDanglingVariable(&b[i])
	}

	var res, v Variable
	res = cs.Constant(0) // no constraint is recorded

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
		v = cs.Mul(coeff, b[i])  // no constraint is recorded
		res = cs.Add(v, res)     // no constraint is recorded
		cs.AssertIsBoolean(b[i]) // ensures the b[i]'s are boolean
	}

	return res
}

// Select if b is true, yields i1 else yields i2
func (cs *ConstraintSystem) Select(b Variable, i1, i2 interface{}) Variable {

	cs.completeDanglingVariable(&b)

	// ensures that b is boolean
	cs.AssertIsBoolean(b)

	var res Variable

	switch t1 := i1.(type) {
	case Variable:
		cs.completeDanglingVariable(&t1)
		res = cs.newInternalVariable()
		v := cs.Sub(t1, i2)  // no constraint is recorded
		w := cs.Sub(res, i2) // no constraint is recorded
		//cs.Println("u-v: ", v)
		constraint := r1c.R1C{L: b.getLinExpCopy(), R: v.getLinExpCopy(), O: w.getLinExpCopy(), Solver: r1c.SingleOutput}
		cs.constraints = append(cs.constraints, constraint)
		return res
	default:
		switch t2 := i2.(type) {
		case Variable:
			cs.completeDanglingVariable(&t2)
			res = cs.newInternalVariable()
			v := cs.Sub(t1, t2)  // no constraint is recorded
			w := cs.Sub(res, t2) // no constraint is recorded
			constraint := r1c.R1C{L: b.getLinExpCopy(), R: v.getLinExpCopy(), O: w.getLinExpCopy(), Solver: r1c.SingleOutput}
			cs.constraints = append(cs.constraints, constraint)
			return res
		default:
			// in this case, no constraint is recorded
			n1 := backend.FromInterface(t1)
			n2 := backend.FromInterface(t2)
			diff := n1.Sub(&n2, &n1)
			res = cs.Mul(b, diff) // no constraint is recorded
			res = cs.Add(res, t2) // no constraint is recorded
			return res
		}
	}
}

// Constant will return (and allocate if neccesary) a constant Variable
//
// input can be a Variable or must be convertible to big.Int (see backend.FromInterface)
func (cs *ConstraintSystem) Constant(input interface{}) Variable {

	switch t := input.(type) {
	case Variable:
		cs.completeDanglingVariable(&t)
		return t
	default:
		n := backend.FromInterface(t)
		if n.Cmp(bOne) == 0 {
			return cs.getOneVariable()
		}
		return cs.mulConstant(n, cs.getOneVariable())
	}
}

// AssertIsEqual adds an assertion in the constraint system (i1 == i2)
func (cs *ConstraintSystem) AssertIsEqual(i1, i2 interface{}) {

	// encoded as L * R == O
	// set L = i1
	// set R = 1
	// set O = i2

	// we don't do just "cs.Sub(i1,i2)" to allow proper logging
	debugInfo := logEntry{}

	l := cs.Constant(i1) // no constraint is recorded
	r := cs.Constant(1)  // no constraint is recorded
	o := cs.Constant(i2) // no constraint is recorded
	constraint := r1c.R1C{L: l.getLinExpCopy(), R: r.getLinExpCopy(), O: o.getLinExpCopy(), Solver: r1c.SingleOutput}

	debugInfo.format += "["
	for i := 0; i < len(l.linExp); i++ {
		if i > 0 {
			debugInfo.format += " + "
		}
		c := cs.coeffs[l.linExp[i].CoeffID()]
		debugInfo.format += fmt.Sprintf("(%%s * %s)", c.String())
		debugInfo.toResolve = append(debugInfo.toResolve, l.linExp[i])
	}
	debugInfo.format += " != "
	for i := 0; i < len(o.linExp); i++ {
		if i > 0 {
			debugInfo.format += " + "
		}
		c := cs.coeffs[o.linExp[i].CoeffID()]
		debugInfo.format += fmt.Sprintf("(%%s * %s)", c.String())
		debugInfo.toResolve = append(debugInfo.toResolve, o.linExp[i])
	}
	debugInfo.format += "]"

	cs.addAssertion(constraint, debugInfo)
}

// AssertIsBoolean adds an assertion in the constraint system (v == 0 || v == 1)
func (cs *ConstraintSystem) AssertIsBoolean(v Variable) {

	cs.completeDanglingVariable(&v)

	if v.isBoolean {
		return
	}

	_v := cs.Sub(1, v)  // no variable is recorded in the cs
	o := cs.Constant(0) // no variable is recorded in the cs
	v.isBoolean = true

	constraint := r1c.R1C{L: v.getLinExpCopy(), R: _v.getLinExpCopy(), O: o.getLinExpCopy(), Solver: r1c.SingleOutput}

	// prepare debug info to be displayed in case the constraint is not solved
	// debugInfo := logEntry{
	// 	format:    fmt.Sprintf("%%s == (0 or 1)"),
	// 	toResolve: []r1c.Term{r1c.Pack(v.id, 0, v.visibility)},
	// }
	// stack := getCallStack()
	debugInfo := logEntry{
		format:    fmt.Sprintf("error AssertIsBoolean"),
		toResolve: nil,
	}
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		debugInfo.format += "\n" + stack[i]
	}

	cs.addAssertion(constraint, debugInfo)
}

// AssertIsLessOrEqual adds assertion in constraint system  (v <= bound)
//
// bound can be a constant or a Variable
//
// derived from:
// https://github.com/zcash/zips/blOoutputb/master/protocol/protocol.pdf
func (cs *ConstraintSystem) AssertIsLessOrEqual(v Variable, bound interface{}) {

	cs.completeDanglingVariable(&v)

	switch b := bound.(type) {
	case Variable:
		cs.completeDanglingVariable(&b)
		cs.mustBeLessOrEqVar(v, b)
	default:
		cs.mustBeLessOrEqCst(v, backend.FromInterface(b))
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

	zero := cs.Constant(0)

	for i := nbBits - 1; i >= 0; i-- {

		p1 := cs.Mul(p[i+1], binw[i])
		p[i] = cs.Select(binbound[i], p1, p[i+1])
		t := cs.Select(binbound[i], zero, p[i+1])

		l := cs.getOneVariable()
		l = cs.Sub(l, t)       // no constraint is recorded
		l = cs.Sub(l, binw[i]) // no constraint is recorded

		r := binw[i]

		o := cs.Constant(0) // no constraint is recorded

		constraint := r1c.R1C{L: l.getLinExpCopy(), R: r.getLinExpCopy(), O: o.getLinExpCopy(), Solver: r1c.SingleOutput}
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

				l := cs.getOneVariable()
				l = cs.Sub(l, p[(i+1)*wordSize-j])       // no constraint is recorded
				l = cs.Sub(l, vBits[(i+1)*wordSize-1-j]) // no constraint is recorded

				r := vBits[(i+1)*wordSize-1-j]
				o := cs.Constant(0)
				constraint := r1c.R1C{L: l.linExp, R: r.linExp, O: o.linExp, Solver: r1c.SingleOutput}
				cs.addAssertion(constraint, debugInfo)

			} else {
				p[(i+1)*wordSize-1-j] = cs.Mul(p[(i+1)*wordSize-j], vBits[(i+1)*wordSize-1-j])
			}
		}
	}
}
