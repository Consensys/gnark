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
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// Add returns res = i1+i2+...in
func (cs *constraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	// extract compiled.Variables from input
	vars, s := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	// allocate resulting Variable
	t := false
	res := compiled.Variable{LinExp: make([]compiled.Term, 0, s), IsBoolean: &t}

	for _, v := range vars {
		l := v.Clone()
		res.LinExp = append(res.LinExp, l.LinExp...)
	}

	res = cs.reduce(res)

	if cs.Backend() == backend.PLONK {
		if len(res.LinExp) == 1 {
			return res
		}
		_res := cs.newInternalVariable()
		cs.constraints = append(cs.constraints, newR1C(cs.one(), res, _res))
		return _res
	}

	return res
}

// Neg returns -i
func (cs *constraintSystem) Neg(i interface{}) Variable {
	vars, _ := cs.toVariables(i)

	if vars[0].IsConstant() {
		n := cs.constantValue(vars[0])
		n.Neg(n)
		return cs.constant(n)
	}

	// ok to pass pointer since if i is boolean constrained later, so must be res
	res := compiled.Variable{LinExp: cs.negateLinExp(vars[0].LinExp), IsBoolean: vars[0].IsBoolean}

	return res
}

// Sub returns res = i1 - i2
func (cs *constraintSystem) Sub(i1, i2 interface{}, in ...interface{}) Variable {

	// extract compiled.Variables from input
	vars, s := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	// allocate resulting Variable
	t := false
	res := compiled.Variable{
		LinExp:    make([]compiled.Term, 0, s),
		IsBoolean: &t,
	}

	c := vars[0].Clone()
	res.LinExp = append(res.LinExp, c.LinExp...)
	for i := 1; i < len(vars); i++ {
		negLinExp := cs.negateLinExp(vars[i].LinExp)
		res.LinExp = append(res.LinExp, negLinExp...)
	}

	// reduce linear expression
	res = cs.reduce(res)

	if cs.Backend() == backend.PLONK {
		if len(res.LinExp) == 1 {
			return res
		}
		_res := cs.newInternalVariable()
		cs.constraints = append(cs.constraints, newR1C(cs.one(), res, _res))
		return _res
	}

	return res
}

// Mul returns res = i1 * i2 * ... in
func (cs *constraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {
	vars, _ := cs.toVariables(append([]interface{}{i1, i2}, in...)...)

	mul := func(v1, v2 compiled.Variable) compiled.Variable {

		// v1 and v2 are both unknown, this is the only case we add a constraint
		if !v1.IsConstant() && !v2.IsConstant() {
			res := cs.newInternalVariable()
			cs.constraints = append(cs.constraints, newR1C(v1, v2, res))
			return res
		}

		// v1 and v2 are constants, we multiply big.Int values and return resulting constant
		if v1.IsConstant() && v2.IsConstant() {
			b1 := cs.constantValue(v1)
			b2 := cs.constantValue(v2)

			b1.Mul(b1, b2).Mod(b1, cs.curveID.Info().Fr.Modulus())
			return cs.constant(b1).(compiled.Variable)
		}

		// ensure v2 is the constant
		if v1.IsConstant() {
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

func (cs *constraintSystem) mulConstant(v1, constant compiled.Variable) compiled.Variable {
	// multiplying a Variable by a constant -> we updated the coefficients in the linear expression
	// leading to that Variable
	res := v1.Clone()
	lambda := cs.constantValue(constant)

	for i, t := range v1.LinExp {
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
		res.LinExp[i] = compiled.Pack(vID, cs.coeffID(&newCoeff), visibility)
	}
	t := false
	res.IsBoolean = &t
	return res
}

// Inverse returns res = inverse(v)
func (cs *constraintSystem) Inverse(i1 interface{}) Variable {
	vars, _ := cs.toVariables(i1)

	if vars[0].IsConstant() {
		// c := vars[0].constantValue(cs)
		c := cs.constantValue(vars[0])
		if c.IsUint64() && c.Uint64() == 0 {
			panic("inverse by constant(0)")
		}

		c.ModInverse(c, cs.curveID.Info().Fr.Modulus())
		return cs.constant(c)
	}

	// allocate resulting Variable
	res := cs.newInternalVariable()

	debug := cs.addDebugInfo("inverse", vars[0], "*", res, " == 1")
	cs.addConstraint(newR1C(res, vars[0], cs.one()), debug)

	return res
}

// Div returns res = i1 / i2
func (cs *constraintSystem) Div(i1, i2 interface{}) Variable {
	vars, _ := cs.toVariables(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	if !v2.IsConstant() {
		res := cs.newInternalVariable()
		debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)
		v2Inv := cs.newInternalVariable()
		// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
		cs.addConstraint(newR1C(cs.one(), v2, v2Inv), debug)
		cs.addConstraint(newR1C(v1, v2Inv, res), debug)
		return res
	}

	// v2 is constant
	b2 := cs.constantValue(v2)
	if b2.IsUint64() && b2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := cs.curveID.Info().Fr.Modulus()
	b2.ModInverse(b2, q)

	if v1.IsConstant() {
		b2.Mul(b2, cs.constantValue(v1)).Mod(b2, q)
		return cs.constant(b2)
	}

	// v1 is not constant
	return cs.mulConstant(v1, cs.constant(b2).(compiled.Variable))
}

func (cs *constraintSystem) DivUnchecked(i1, i2 interface{}) Variable {
	vars, _ := cs.toVariables(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	if !v2.IsConstant() {
		res := cs.newInternalVariable()
		debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)
		// note that here we don't ensure that divisor is != 0
		cs.addConstraint(newR1C(v2, res, v1), debug)
		return res
	}

	// v2 is constant
	b2 := cs.constantValue(v2)
	if b2.IsUint64() && b2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := cs.curveID.Info().Fr.Modulus()
	b2.ModInverse(b2, q)

	if v1.IsConstant() {
		b2.Mul(b2, cs.constantValue(v1)).Mod(b2, q)
		return cs.constant(b2)
	}

	// v1 is not constant
	return cs.mulConstant(v1, cs.constant(b2).(compiled.Variable))
}

// Xor compute the XOR between two compiled.Variables
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

// Or compute the OR between two compiled.Variables
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

// And compute the AND between two compiled.Variables
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
	if a.IsConstant() {
		// c := a.constantValue(cs)
		c := cs.constantValue(a)
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
	if a.IsConstant() {
		c := cs.constantValue(a)
		b := make([]compiled.Variable, nbBits)
		for i := 0; i < len(b); i++ {
			b[i] = cs.constant(c.Bit(i)).(compiled.Variable)
		}
		return toSliceOfVariables(b)
	}

	return cs.toBinary(a, nbBits, false)
}

// toBinary is equivalent to ToBinary, exept the returned bits are NOT boolean constrained.
func (cs *constraintSystem) toBinary(a compiled.Variable, nbBits int, unsafe bool) []Variable {

	if a.IsConstant() {
		return cs.ToBinary(a, nbBits)
	}

	// ensure a is set
	a.AssertIsSet()

	// allocate the resulting compiled.Variables and bit-constraint them
	b := make([]Variable, nbBits)
	sb := make([]interface{}, nbBits)
	var c big.Int
	c.SetUint64(1)
	for i := 0; i < nbBits; i++ {
		b[i] = cs.NewHint(hint.IthBit, a, i)
		sb[i] = cs.Mul(b[i], c)
		c.Lsh(&c, 1)
		if !unsafe {
			cs.AssertIsBoolean(b[i])
		}
	}

	//var Σbi compiled.Variable
	var Σbi Variable
	if nbBits == 2 {
		Σbi = cs.Add(sb[0], sb[1])
	} else {
		Σbi = cs.Add(sb[0], sb[1], sb[2:]...)
	}
	cs.AssertIsEqual(Σbi, a)

	// record the constraint Σ (2**i * b[i]) == a
	return b

}

func toSliceOfVariables(v []compiled.Variable) []Variable {
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
		b[i].AssertIsSet()
	}

	// res = Σ (2**i * b[i])

	var res, v Variable
	res = cs.constant(0) // no constraint is recorded

	var c big.Int
	c.SetUint64(1)

	L := make([]compiled.Term, len(b))
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

	if vars[1].IsConstant() && vars[2].IsConstant() {
		n1 := cs.constantValue(vars[1])
		n2 := cs.constantValue(vars[2])
		diff := n1.Sub(n1, n2)
		res := cs.Mul(b, diff)     // no constraint is recorded
		res = cs.Add(res, vars[2]) // no constraint is recorded
		return res
	}

	v := cs.Sub(vars[1], vars[2]) // no constraint is recorded
	w := cs.Mul(b, v)
	return cs.Add(w, vars[2])

}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (cs *constraintSystem) Lookup2(b0, b1 interface{}, i0, i1, i2, i3 interface{}) Variable {
	vars, _ := cs.toVariables(b0, b1, i0, i1, i2, i3)
	s0, s1 := vars[0], vars[1]
	in0, in1, in2, in3 := vars[2], vars[3], vars[4], vars[5]

	// ensure that bits are actually bits. Adds no constraints if the variables
	// are already constrained.
	cs.AssertIsBoolean(s0)
	cs.AssertIsBoolean(s1)

	// two-bit lookup for the general case can be done with three constraints as
	// following:
	//    (1) (in3 - in2 - in1 + in0) * s1 = tmp1 - in1 + in0
	//    (2) tmp1 * s0 = tmp2
	//    (3) (in2 - in0) * s1 = RES - tmp2 - in0
	// the variables tmp1 and tmp2 are new internal variables and the variables
	// RES will be the returned result

	tmp1 := cs.Add(in3, in0)
	tmp1 = cs.Sub(tmp1, in2, in1)
	tmp1 = cs.Mul(tmp1, s1)
	tmp1 = cs.Add(tmp1, in1)
	tmp1 = cs.Sub(tmp1, in0) // (1) tmp1 = s1 * (in3 - in2 - in1 + in0) + in1 - in0
	tmp2 := cs.Mul(tmp1, s0) // (2) tmp2 = tmp1 * s0
	res := cs.Sub(in2, in0)
	res = cs.Mul(res, s1)
	res = cs.Add(res, tmp2, in0) // (3) res = (v2 - v0) * s1 + tmp2 + in0
	return res
}

// IsConstant returns true if v is a constant known at compile time
func (cs *constraintSystem) IsConstant(v Variable) bool {
	if _v, ok := v.(compiled.Variable); ok {
		return _v.IsConstant()
	}
	// it's not a wire, it's another golang type, we consider it constant.
	// TODO we may want to use the struct parser to ensure this Variable interface doesn't contain fields which are
	// compiled.Variable
	return true
}

// ConstantValue returns the big.Int value of v.
// Will panic if v.IsConstant() == false
func (cs *constraintSystem) ConstantValue(v Variable) *big.Int {
	if _v, ok := v.(compiled.Variable); ok {
		return cs.constantValue(_v)
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
	case compiled.Variable:
		t.AssertIsSet()
		return t
	default:
		n := FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return cs.one()
		}
		r := cs.one()
		r.LinExp[0] = cs.setCoeff(r.LinExp[0], &n)
		return r
	}
}

// toVariables return Variable corresponding to inputs and the total size of the linear expressions
func (cs *constraintSystem) toVariables(in ...interface{}) ([]compiled.Variable, int) {
	r := make([]compiled.Variable, 0, len(in))
	s := 0
	e := func(i interface{}) {
		v := cs.constant(i).(compiled.Variable)
		r = append(r, v)
		s += len(v.LinExp)
	}
	// e(i1)
	// e(i2)
	for i := 0; i < len(in); i++ {
		e(in[i])
	}
	return r, s
}

// returns -le, the result is a copy
func (cs *constraintSystem) negateLinExp(l []compiled.Term) []compiled.Term {
	res := make([]compiled.Term, len(l))
	var lambda big.Int
	for i, t := range l {
		cID, vID, visibility := t.Unpack()
		lambda.Neg(&cs.coeffs[cID])
		cID = cs.coeffID(&lambda)
		res[i] = compiled.Pack(vID, cID, visibility)
	}
	return res
}
