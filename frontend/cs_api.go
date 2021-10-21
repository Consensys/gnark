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

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// Add returns res = i1+i2+...in
func (cs *constraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	// extract variables from input
	vars, s := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	// allocate resulting variable
	res := Variable{
		linExp: make(compiled.LinearExpression, 0, s),
	}

	for _, v := range vars {
		res.linExp = append(res.linExp, v.linExp.Clone()...)
	}

	res.linExp = cs.reduce(res.linExp)

	return res
}

// Neg returns -i
func (cs *constraintSystem) Neg(i interface{}) Variable {

	var res Variable

	switch t := i.(type) {
	case Variable:
		t.assertIsSet(cs)
		res.linExp = cs.negateLinExp(t.linExp)
	default:
		n := FromInterface(t)
		n.Neg(&n)
		if n.IsUint64() && n.Uint64() == 1 {
			return cs.one()
		}
		res = cs.Constant(n)
	}
	return res
}

// returns -le, the result is a copy
func (cs *constraintSystem) negateLinExp(l compiled.LinearExpression) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(l))
	var coeff, coeffCopy big.Int
	for i, t := range l {
		cID, vID, visibility := t.Unpack()
		coeff = cs.coeffs[cID]
		// TODO fast path for known coeffs
		coeffCopy.Neg(&coeff)
		res[i] = cs.makeTerm(Variable{visibility: visibility, id: vID}, &coeffCopy)
	}
	return res
}

// Sub returns res = i1 - i2
func (cs *constraintSystem) Sub(i1, i2 interface{}, in ...interface{}) Variable {

	// extract variables from input
	vars, s := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	// allocate resulting variable
	res := Variable{
		linExp: make(compiled.LinearExpression, 0, s),
	}

	res.linExp = append(res.linExp, vars[0].linExp.Clone()...)
	for i := 1; i < len(vars); i++ {
		negLinExp := cs.negateLinExp(vars[i].linExp)
		res.linExp = append(res.linExp, negLinExp...)
	}

	// reduce linear expression
	res.linExp = cs.reduce(res.linExp)

	return res
}

func (cs *constraintSystem) mulConstant(v1, constant Variable) Variable {
	// sanity check
	if v1.isConstant() || !constant.isConstant() {
		panic("v1 must not be constant, constant must be.")
	}

	linExp := v1.linExp.Clone()

	lambda := constant.constantValue(cs)

	for i, t := range v1.linExp {
		cID, vID, visibility := t.Unpack()
		switch cID {
		case compiled.CoeffIdMinusOne:
			lambda.Neg(lambda)
		case compiled.CoeffIdZero:
			lambda.SetUint64(0)
		case compiled.CoeffIdOne:
			// lambda.Set(lambda)
		case compiled.CoeffIdTwo:
			lambda.Add(lambda, lambda)
		default:
			coeff := cs.coeffs[cID]
			lambda.Mul(&coeff, lambda).Mod(lambda, cs.curveID.Info().Fr.Modulus())
		}
		linExp[i] = cs.makeTerm(Variable{visibility: visibility, id: vID}, lambda)
	}
	return Variable{linExp: linExp}
}

// Mul returns res = i1 * i2 * ... in
func (cs *constraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {
	vars, _ := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	mul := func(v1, v2 Variable) Variable {

		// v1 and v2 are both unknown, this is the only case we add a constraint
		if !v1.isConstant() && !v2.isConstant() {
			res := cs.newInternalVariable()
			cs.constraints = append(cs.constraints, newR1C(v1, v2, res))
			return res
		}

		// v1 and v2 are constants, we multiply big.Int values and return resulting constant
		if v1.isConstant() && v2.isConstant() {
			b1 := v1.constantValue(cs)
			b2 := v2.constantValue(cs)

			b1.Mul(b1, b2).Mod(b1, cs.curveID.Info().Fr.Modulus())
			return cs.Constant(b1)
		}

		// multiplying a variable by a constant -> we updated the coefficients in the linear expression
		// leading to that variable

		// ensure v2 is the constant
		if v1.isConstant() {
			v1, v2 = v2, v1
		}

		return cs.mulConstant(v1, v2)
	}

	res := mul(vars[0], vars[1])

	for i := 2; i < len(vars); i++ {
		res = mul(res, vars[i])
	}

	return res
}

// Inverse returns res = inverse(v)
func (cs *constraintSystem) Inverse(v Variable) Variable {
	v.assertIsSet(cs)

	// allocate resulting variable
	res := cs.newInternalVariable()

	debug := cs.addDebugInfo("inverse", v, "*", res, " == 1")

	cs.addConstraint(newR1C(v, res, cs.one()), debug)

	return res
}

// Div returns res = i1 / i2
func (cs *constraintSystem) Div(i1, i2 interface{}) Variable {
	// allocate resulting variable
	res := cs.newInternalVariable()

	v1 := cs.Constant(i1)
	v2 := cs.Constant(i2)
	debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)

	v2Inv := cs.newInternalVariable()

	cs.addConstraint(newR1C(v2, v2Inv, cs.one()), debug)
	cs.addConstraint(newR1C(v1, v2Inv, res), debug)

	return res
}

func (cs *constraintSystem) DivUnchecked(i1, i2 interface{}) Variable {
	// allocate resulting variable
	res := cs.newInternalVariable()

	v1 := cs.Constant(i1)
	v2 := cs.Constant(i2)

	// TODO if v1 or v2 is a constant, this shouldn't add a constraint.

	debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)

	cs.addConstraint(newR1C(v2, res, v1), debug)

	return res
}

// Xor compute the XOR between two variables
func (cs *constraintSystem) Xor(a, b Variable) Variable {

	a.assertIsSet(cs)
	b.assertIsSet(cs)

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.newInternalVariable()
	v1 := cs.Mul(2, a)   // no constraint recorded
	v2 := cs.Add(a, b)   // no constraint recorded
	v2 = cs.Sub(v2, res) // no constraint recorded

	cs.constraints = append(cs.constraints, newR1C(v1, b, v2))

	return res
}

// Or compute the OR between two variables
func (cs *constraintSystem) Or(a, b Variable) Variable {

	a.assertIsSet(cs)
	b.assertIsSet(cs)

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.newInternalVariable()
	v1 := cs.Sub(1, a)
	v2 := cs.Sub(res, a)

	cs.constraints = append(cs.constraints, newR1C(b, v1, v2))

	return res
}

// And compute the AND between two variables
func (cs *constraintSystem) And(a, b Variable) Variable {

	a.assertIsSet(cs)
	b.assertIsSet(cs)

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.Mul(a, b)

	return res
}

// IsZero returns 1 if a is zero, 0 otherwise
func (cs *constraintSystem) IsZero(a Variable) Variable {
	a.assertIsSet(cs)
	debug := cs.addDebugInfo("isZero", a)

	//m * (1 - m) = 0       // constrain m to be 0 or 1
	// a * m = 0            // constrain m to be 0 if a != 0
	// _ = inverse(m + a) 	// constrain m to be 1 if a == 0

	// m is computed by the solver such that m = 1 - a^(modulus - 1)
	m := cs.NewHint(hint.IsZero, a)
	cs.addConstraint(newR1C(a, m, cs.Constant(0)), debug)

	cs.AssertIsBoolean(m)
	ma := cs.Add(m, a)
	_ = cs.Inverse(ma)
	return m

}

// ToBinary unpacks a variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (cs *constraintSystem) ToBinary(a Variable, n ...int) []Variable {
	// ensure a is set
	a.assertIsSet(cs)

	nbBits := cs.bitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	// allocate the resulting variables and bit-constraint them
	b := make([]Variable, nbBits)
	for i := 0; i < nbBits; i++ {
		b[i] = cs.NewHint(hint.IthBit, a, i)
		cs.AssertIsBoolean(b[i])
	}

	// here what we do is we add a single constraint where
	// Σ (2**i * b[i]) == a
	var c big.Int
	c.SetUint64(1)

	var Σbi Variable
	Σbi.linExp = make(compiled.LinearExpression, nbBits)

	for i := 0; i < nbBits; i++ {
		Σbi.linExp[i] = cs.makeTerm(Variable{visibility: compiled.Internal, id: b[i].id}, &c)
		c.Lsh(&c, 1)
	}

	debug := cs.addDebugInfo("toBinary", Σbi, " == ", a)

	// record the constraint Σ (2**i * b[i]) == a
	cs.addConstraint(newR1C(Σbi, cs.one(), a), debug)
	return b

}

// toBinaryUnsafe is equivalent to ToBinary, exept the returned bits are NOT boolean constrained.
func (cs *constraintSystem) toBinaryUnsafe(a Variable, nbBits int) []Variable {
	// ensure a is set
	a.assertIsSet(cs)

	// allocate the resulting variables and bit-constraint them
	b := make([]Variable, nbBits)
	for i := 0; i < nbBits; i++ {
		b[i] = cs.NewHint(hint.IthBit, a, i)
	}

	// here what we do is we add a single constraint where
	// Σ (2**i * b[i]) == a
	var c big.Int
	c.SetUint64(1)

	var Σbi Variable
	Σbi.linExp = make(compiled.LinearExpression, nbBits)

	for i := 0; i < nbBits; i++ {
		Σbi.linExp[i] = cs.makeTerm(Variable{visibility: compiled.Internal, id: b[i].id}, &c)
		c.Lsh(&c, 1)
	}

	debug := cs.addDebugInfo("toBinary", Σbi, " == ", a)

	// record the constraint Σ (2**i * b[i]) == a
	cs.addConstraint(newR1C(Σbi, cs.one(), a), debug)
	return b

}

// FromBinary packs b, seen as a fr.Element in little endian
func (cs *constraintSystem) FromBinary(b ...Variable) Variable {
	// ensure inputs are set
	for i := 0; i < len(b); i++ {
		b[i].assertIsSet(cs)
	}

	// res = Σ (2**i * b[i])

	var res, v Variable
	res = cs.Constant(0) // no constraint is recorded

	var c big.Int
	c.SetUint64(1)

	L := make(compiled.LinearExpression, len(b))
	for i := 0; i < len(L); i++ {
		v = cs.Mul(c, b[i])      // no constraint is recorded
		res = cs.Add(v, res)     // no constraint is recorded
		cs.AssertIsBoolean(b[i]) // ensures the b[i]'s are boolean
		c.Lsh(&c, 1)
	}

	return res
}

// Select if b is true, yields i1 else yields i2
func (cs *constraintSystem) Select(b Variable, i1, i2 interface{}) Variable {

	b.assertIsSet(cs)

	// ensures that b is boolean
	cs.AssertIsBoolean(b)

	var res Variable

	switch t1 := i1.(type) {
	case Variable:
		t1.assertIsSet(cs)
		res = cs.newInternalVariable()
		v := cs.Sub(t1, i2)  // no constraint is recorded
		w := cs.Sub(res, i2) // no constraint is recorded
		//cs.Println("u-v: ", v)
		cs.constraints = append(cs.constraints, newR1C(v, b, w))
		return res
	default:
		switch t2 := i2.(type) {
		case Variable:
			t2.assertIsSet(cs)
			res = cs.newInternalVariable()
			v := cs.Sub(t1, t2)  // no constraint is recorded
			w := cs.Sub(res, t2) // no constraint is recorded
			cs.constraints = append(cs.constraints, newR1C(v, b, w))
			return res
		default:
			// in this case, no constraint is recorded
			n1 := FromInterface(t1)
			n2 := FromInterface(t2)
			diff := n1.Sub(&n2, &n1)
			res = cs.Mul(b, diff) // no constraint is recorded
			res = cs.Add(res, t2) // no constraint is recorded
			return res
		}
	}
}

// Constant will return (and allocate if neccesary) a Variable from given value
//
// if input is already a Variable, does nothing
// else, attempts to convert input to a big.Int (see FromInterface) and returns a Constant Variable
//
// a Constant variable does NOT necessary allocate a Variable in the ConstraintSystem
// it is in the form ONE_WIRE * coeff
func (cs *constraintSystem) Constant(input interface{}) Variable {

	switch t := input.(type) {
	case Variable:
		t.assertIsSet(cs)
		return t
	default:
		n := FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return cs.one()
		}
		return Variable{linExp: compiled.LinearExpression{
			cs.makeTerm(Variable{visibility: compiled.Public, id: 0}, &n),
		}}
	}
}

// toVariables return Variable corresponding to inputs and the total size of the linear expressions
func (cs *constraintSystem) toVariables(in ...interface{}) ([]Variable, int) {
	r := make([]Variable, 0, len(in))
	s := 0
	e := func(i interface{}) {
		v := cs.Constant(i)
		r = append(r, v)
		s += len(v.linExp)
	}
	// e(i1)
	// e(i2)
	for i := 0; i < len(in); i++ {
		e(in[i])
	}
	return r, s
}
