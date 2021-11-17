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

	// allocate resulting Variable
	res := variable{linExp: make(compiled.LinearExpression, 0, s)}

	for _, v := range vars {
		res.linExp = append(res.linExp, v.linExp.Clone()...)
	}

	res.linExp = cs.reduce(res.linExp)

	return res
}

// Neg returns -i
func (cs *constraintSystem) Neg(i interface{}) Variable {
	vars, _ := cs.toVariables(i)

	if vars[0].isConstant() {
		n := vars[0].constantValue(cs)
		n.Neg(n)
		return cs.constant(n)
	}

	return variable{linExp: cs.negateLinExp(vars[0].linExp)}
}

// Sub returns res = i1 - i2
func (cs *constraintSystem) Sub(i1, i2 interface{}, in ...interface{}) Variable {

	// extract variables from input
	vars, s := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	// allocate resulting Variable
	res := variable{
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

// Mul returns res = i1 * i2 * ... in
func (cs *constraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {
	vars, _ := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	mul := func(v1, v2 variable) variable {

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
			return cs.constant(b1).(variable)
		}

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

func (cs *constraintSystem) mulConstant(v1, constant variable) variable {
	// multiplying a Variable by a constant -> we updated the coefficients in the linear expression
	// leading to that Variable
	linExp := v1.linExp.Clone()
	lambda := constant.constantValue(cs)

	for i, t := range v1.linExp {
		cID, vID, visibility := t.Unpack()
		var newCoeff big.Int
		switch cID {
		case compiled.CoeffIdMinusOne:
			newCoeff.Neg(lambda)
		case compiled.CoeffIdZero:
			newCoeff.SetUint64(0)
		case compiled.CoeffIdOne:
			newCoeff.Set(lambda)
		case compiled.CoeffIdTwo:
			newCoeff.Add(lambda, lambda)
		default:
			coeff := cs.coeffs[cID]
			newCoeff.Mul(&coeff, lambda)
		}
		linExp[i] = cs.makeTerm(variable{visibility: visibility, id: vID}, &newCoeff)
	}
	return variable{linExp: linExp}
}

// Inverse returns res = inverse(v)
func (cs *constraintSystem) Inverse(i1 interface{}) Variable {
	vars, _ := cs.toVariables(i1)

	if vars[0].isConstant() {
		c := vars[0].constantValue(cs)
		if c.IsUint64() && c.Uint64() == 0 {
			panic("inverse by constant(0)")
		}

		c.ModInverse(c, cs.curveID.Info().Fr.Modulus())
		return cs.constant(c)
	}

	// allocate resulting Variable
	res := cs.newInternalVariable()

	debug := cs.addDebugInfo("inverse", vars[0], "*", res, " == 1")
	cs.addConstraint(newR1C(vars[0], res, cs.one()), debug)

	return res
}

// Div returns res = i1 / i2
func (cs *constraintSystem) Div(i1, i2 interface{}) Variable {
	vars, _ := cs.toVariables(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	if !v2.isConstant() {
		res := cs.newInternalVariable()
		debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)
		v2Inv := cs.newInternalVariable()
		// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
		cs.addConstraint(newR1C(v2, v2Inv, cs.one()), debug)
		cs.addConstraint(newR1C(v1, v2Inv, res), debug)
		return res
	}

	// v2 is constant
	b2 := v2.constantValue(cs)
	if b2.IsUint64() && b2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := cs.curveID.Info().Fr.Modulus()
	b2.ModInverse(b2, q)

	if v1.isConstant() {
		b2.Mul(b2, v1.constantValue(cs)).Mod(b2, q)
		return cs.constant(b2)
	}

	// v1 is not constant
	return cs.mulConstant(v1, cs.constant(b2).(variable))
}

func (cs *constraintSystem) DivUnchecked(i1, i2 interface{}) Variable {
	vars, _ := cs.toVariables(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	if !v2.isConstant() {
		res := cs.newInternalVariable()
		debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)
		// note that here we don't ensure that divisor is != 0
		cs.addConstraint(newR1C(v2, res, v1), debug)
		return res
	}

	// v2 is constant
	b2 := v2.constantValue(cs)
	if b2.IsUint64() && b2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := cs.curveID.Info().Fr.Modulus()
	b2.ModInverse(b2, q)

	if v1.isConstant() {
		b2.Mul(b2, v1.constantValue(cs)).Mod(b2, q)
		return cs.constant(b2)
	}

	// v1 is not constant
	return cs.mulConstant(v1, cs.constant(b2).(variable))
}

// Xor compute the XOR between two variables
func (cs *constraintSystem) Xor(_a, _b Variable) Variable {

	vars, _ := cs.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

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
func (cs *constraintSystem) Or(_a, _b Variable) Variable {
	vars, _ := cs.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.newInternalVariable()
	v1 := cs.Sub(1, a)
	v2 := cs.Sub(res, a)

	cs.constraints = append(cs.constraints, newR1C(b, v1, v2))

	return res
}

// And compute the AND between two variables
func (cs *constraintSystem) And(_a, _b Variable) Variable {
	vars, _ := cs.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.Mul(a, b)

	return res
}

// IsZero returns 1 if i1 is zero, 0 otherwise
func (cs *constraintSystem) IsZero(i1 interface{}) Variable {
	vars, _ := cs.toVariables(i1)
	a := vars[0]
	if a.isConstant() {
		c := a.constantValue(cs)
		if c.IsUint64() && c.Uint64() == 0 {
			return cs.constant(1)
		}
		return cs.constant(0)
	}

	debug := cs.addDebugInfo("isZero", a)

	//m * (1 - m) = 0       // constrain m to be 0 or 1
	// a * m = 0            // constrain m to be 0 if a != 0
	// _ = inverse(m + a) 	// constrain m to be 1 if a == 0

	// m is computed by the solver such that m = 1 - a^(modulus - 1)
	m := cs.NewHint(hint.IsZero, a)
	cs.addConstraint(newR1C(a, m, cs.constant(0)), debug)

	cs.AssertIsBoolean(m)
	ma := cs.Add(m, a)
	_ = cs.Inverse(ma)
	return m

}

// ToBinary unpacks a Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (cs *constraintSystem) ToBinary(i1 interface{}, n ...int) []Variable {
	// nbBits
	nbBits := cs.bitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	vars, _ := cs.toVariables(i1)
	a := vars[0]

	// if a is a constant, work with the big int value.
	if a.isConstant() {
		c := a.constantValue(cs)
		b := make([]variable, nbBits)
		for i := 0; i < len(b); i++ {
			b[i] = cs.constant(c.Bit(i)).(variable)
		}
		return toSliceOfVariables(b)
	}

	// allocate the resulting variables and bit-constraint them
	b := make([]variable, nbBits)
	for i := 0; i < nbBits; i++ {
		b[i] = cs.NewHint(hint.IthBit, a, i).(variable)
		cs.AssertIsBoolean(b[i])
	}

	// here what we do is we add a single constraint where
	// Σ (2**i * b[i]) == a
	var c big.Int
	c.SetUint64(1)

	var Σbi variable
	Σbi.linExp = make(compiled.LinearExpression, nbBits)

	for i := 0; i < nbBits; i++ {
		Σbi.linExp[i] = cs.makeTerm(variable{visibility: compiled.Internal, id: b[i].id}, &c)
		c.Lsh(&c, 1)
	}

	debug := cs.addDebugInfo("toBinary", Σbi, " == ", a)

	// record the constraint Σ (2**i * b[i]) == a
	cs.addConstraint(newR1C(Σbi, cs.one(), a), debug)
	return toSliceOfVariables(b)

}

// toBinaryUnsafe is equivalent to ToBinary, exept the returned bits are NOT boolean constrained.
func (cs *constraintSystem) toBinaryUnsafe(a variable, nbBits int) []Variable {
	if a.isConstant() {
		return cs.ToBinary(a, nbBits)
	}
	// ensure a is set
	a.assertIsSet(cs)

	// allocate the resulting variables and bit-constraint them
	b := make([]variable, nbBits)
	for i := 0; i < nbBits; i++ {
		b[i] = cs.NewHint(hint.IthBit, a, i).(variable)
	}

	// here what we do is we add a single constraint where
	// Σ (2**i * b[i]) == a
	var c big.Int
	c.SetUint64(1)

	var Σbi variable
	Σbi.linExp = make(compiled.LinearExpression, nbBits)

	for i := 0; i < nbBits; i++ {
		Σbi.linExp[i] = cs.makeTerm(variable{visibility: compiled.Internal, id: b[i].id}, &c)
		c.Lsh(&c, 1)
	}

	debug := cs.addDebugInfo("toBinary", Σbi, " == ", a)

	// record the constraint Σ (2**i * b[i]) == a
	cs.addConstraint(newR1C(Σbi, cs.one(), a), debug)
	return toSliceOfVariables(b)

}

func toSliceOfVariables(v []variable) []Variable {
	// TODO this is ugly.
	r := make([]Variable, len(v))
	for i := 0; i < len(v); i++ {
		r[i] = v[i]
	}
	return r
}

// FromBinary packs b, seen as a fr.Element in little endian
func (cs *constraintSystem) FromBinary(_b ...interface{}) Variable {
	b, _ := cs.toVariables(_b...)

	// ensure inputs are set
	for i := 0; i < len(b); i++ {
		b[i].assertIsSet(cs)
	}

	// res = Σ (2**i * b[i])

	var res, v Variable
	res = cs.constant(0) // no constraint is recorded

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

// Select if i0 is true, yields i1 else yields i2
func (cs *constraintSystem) Select(i0, i1, i2 interface{}) Variable {
	vars, _ := cs.toVariables(i0, i1, i2)
	b := vars[0]

	// ensures that b is boolean
	cs.AssertIsBoolean(b)

	// this doesn't work.
	// if b.isConstant() {
	// 	c := b.constantValue(cs)
	// 	if c.Uint64() == 0 {
	// 		return vars[2]
	// 	}
	// 	return vars[1]
	// }

	if vars[1].isConstant() && vars[2].isConstant() {
		n1 := vars[1].constantValue(cs)
		n2 := vars[2].constantValue(cs)
		diff := n1.Sub(n1, n2)
		res := cs.Mul(b, diff)     // no constraint is recorded
		res = cs.Add(res, vars[2]) // no constraint is recorded
		return res
	}

	res := cs.newInternalVariable()
	v := cs.Sub(vars[1], vars[2]) // no constraint is recorded
	w := cs.Sub(res, vars[2])     // no constraint is recorded
	cs.constraints = append(cs.constraints, newR1C(v, b, w))
	return res

}

// IsConstant returns true if v is a constant known at compile time
func (cs *constraintSystem) IsConstant(v Variable) bool {
	if _v, ok := v.(variable); ok {
		return _v.isConstant()
	}
	// it's not a wire, it's another golang type, we consider it constant.
	// TODO we may want to use the struct parser to ensure this Variable interface doesn't contain fields which are
	// variable
	return true
}

// ConstantValue returns the big.Int value of v
// will panic if v.IsConstant() == false
func (cs *constraintSystem) ConstantValue(v Variable) *big.Int {
	if _v, ok := v.(variable); ok {
		return _v.constantValue(cs)
	}
	r := FromInterface(v)
	return &r
}

// constant will return (and allocate if neccesary) a Variable from given value
//
// if input is already a Variable, does nothing
// else, attempts to convert input to a big.Int (see FromInterface) and returns a constant Variable
//
// a constant Variable does NOT necessary allocate a Variable in the ConstraintSystem
// it is in the form ONE_WIRE * coeff
func (cs *constraintSystem) constant(input interface{}) Variable {

	switch t := input.(type) {
	case variable:
		t.assertIsSet(cs)
		return t
	default:
		n := FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return cs.one()
		}
		return variable{linExp: compiled.LinearExpression{
			cs.makeTerm(variable{visibility: compiled.Public, id: 0}, &n),
		}}
	}
}

// toVariables return Variable corresponding to inputs and the total size of the linear expressions
func (cs *constraintSystem) toVariables(in ...interface{}) ([]variable, int) {
	r := make([]variable, 0, len(in))
	s := 0
	e := func(i interface{}) {
		v := cs.constant(i).(variable)
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

// returns -le, the result is a copy
func (cs *constraintSystem) negateLinExp(l compiled.LinearExpression) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(l))
	var lambda big.Int
	for i, t := range l {
		cID, vID, visibility := t.Unpack()
		lambda.Neg(&cs.coeffs[cID])
		res[i] = cs.makeTerm(variable{visibility: visibility, id: vID}, &lambda)
	}
	return res
}
