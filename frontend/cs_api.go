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
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// Add returns res = i1+i2+...in
func (system *R1CS) Add(i1, i2 cs.Variable, in ...cs.Variable) cs.Variable {

	// extract cs.Variables from input
	vars, s := system.toVariables(append([]cs.Variable{i1, i2}, in...)...)

	// allocate resulting cs.Variable
	t := false
	res := compiled.Variable{LinExp: make([]compiled.Term, 0, s), IsBoolean: &t}

	for _, v := range vars {
		l := v.Clone()
		res.LinExp = append(res.LinExp, l.LinExp...)
	}

	res = system.reduce(res)

	if system.Backend() == backend.PLONK {
		if len(res.LinExp) == 1 {
			return res
		}
		_res := system.newInternalVariable()
		system.constraints = append(system.constraints, newR1C(system.one(), res, _res))
		return _res
	}

	return res
}

// Neg returns -i
func (system *R1CS) Neg(i cs.Variable) cs.Variable {
	vars, _ := system.toVariables(i)

	if vars[0].IsConstant() {
		n := system.constantValue(vars[0])
		n.Neg(n)
		return system.constant(n)
	}

	// ok to pass pointer since if i is boolean constrained later, so must be res
	res := compiled.Variable{LinExp: system.negateLinExp(vars[0].LinExp), IsBoolean: vars[0].IsBoolean}

	return res
}

// Sub returns res = i1 - i2
func (system *R1CS) Sub(i1, i2 cs.Variable, in ...cs.Variable) cs.Variable {

	// extract cs.Variables from input
	vars, s := system.toVariables(append([]cs.Variable{i1, i2}, in...)...)

	// allocate resulting cs.Variable
	t := false
	res := compiled.Variable{
		LinExp:    make([]compiled.Term, 0, s),
		IsBoolean: &t,
	}

	c := vars[0].Clone()
	res.LinExp = append(res.LinExp, c.LinExp...)
	for i := 1; i < len(vars); i++ {
		negLinExp := system.negateLinExp(vars[i].LinExp)
		res.LinExp = append(res.LinExp, negLinExp...)
	}

	// reduce linear expression
	res = system.reduce(res)

	if system.Backend() == backend.PLONK {
		if len(res.LinExp) == 1 {
			return res
		}
		_res := system.newInternalVariable()
		system.constraints = append(system.constraints, newR1C(system.one(), res, _res))
		return _res
	}

	return res
}

// Mul returns res = i1 * i2 * ... in
func (system *R1CS) Mul(i1, i2 cs.Variable, in ...cs.Variable) cs.Variable {
	vars, _ := system.toVariables(append([]cs.Variable{i1, i2}, in...)...)

	mul := func(v1, v2 compiled.Variable) compiled.Variable {

		// v1 and v2 are both unknown, this is the only case we add a constraint
		if !v1.IsConstant() && !v2.IsConstant() {
			res := system.newInternalVariable()
			system.constraints = append(system.constraints, newR1C(v1, v2, res))
			return res
		}

		// v1 and v2 are constants, we multiply big.Int values and return resulting constant
		if v1.IsConstant() && v2.IsConstant() {
			b1 := system.constantValue(v1)
			b2 := system.constantValue(v2)

			b1.Mul(b1, b2).Mod(b1, system.curveID.Info().Fr.Modulus())
			return system.constant(b1).(compiled.Variable)
		}

		// ensure v2 is the constant
		if v1.IsConstant() {
			v1, v2 = v2, v1
		}

		return system.mulConstant(v1, v2)
	}

	res := mul(vars[0], vars[1])

	for i := 2; i < len(vars); i++ {
		res = mul(res, vars[i])
	}

	return res
}

func (system *R1CS) mulConstant(v1, constant compiled.Variable) compiled.Variable {
	// multiplying a cs.Variable by a constant -> we updated the coefficients in the linear expression
	// leading to that cs.Variable
	res := v1.Clone()
	lambda := system.constantValue(constant)

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
			coeff := system.coeffs[cID]
			newCoeff.Mul(&coeff, lambda)
		}
		res.LinExp[i] = compiled.Pack(vID, system.coeffID(&newCoeff), visibility)
	}
	t := false
	res.IsBoolean = &t
	return res
}

// Inverse returns res = inverse(v)
func (system *R1CS) Inverse(i1 cs.Variable) cs.Variable {
	vars, _ := system.toVariables(i1)

	if vars[0].IsConstant() {
		// c := vars[0].constantValue(cs)
		c := system.constantValue(vars[0])
		if c.IsUint64() && c.Uint64() == 0 {
			panic("inverse by constant(0)")
		}

		c.ModInverse(c, system.curveID.Info().Fr.Modulus())
		return system.constant(c)
	}

	// allocate resulting cs.Variable
	res := system.newInternalVariable()

	debug := system.addDebugInfo("inverse", vars[0], "*", res, " == 1")
	system.addConstraint(newR1C(res, vars[0], system.one()), debug)

	return res
}

// Div returns res = i1 / i2
func (system *R1CS) Div(i1, i2 cs.Variable) cs.Variable {
	vars, _ := system.toVariables(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	if !v2.IsConstant() {
		res := system.newInternalVariable()
		debug := system.addDebugInfo("div", v1, "/", v2, " == ", res)
		v2Inv := system.newInternalVariable()
		// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
		system.addConstraint(newR1C(v2, v2Inv, system.one()), debug)
		system.addConstraint(newR1C(v1, v2Inv, res), debug)
		return res
	}

	// v2 is constant
	b2 := system.constantValue(v2)
	if b2.IsUint64() && b2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := system.curveID.Info().Fr.Modulus()
	b2.ModInverse(b2, q)

	if v1.IsConstant() {
		b2.Mul(b2, system.constantValue(v1)).Mod(b2, q)
		return system.constant(b2)
	}

	// v1 is not constant
	return system.mulConstant(v1, system.constant(b2).(compiled.Variable))
}

func (system *R1CS) DivUnchecked(i1, i2 cs.Variable) cs.Variable {
	vars, _ := system.toVariables(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	if !v2.IsConstant() {
		res := system.newInternalVariable()
		debug := system.addDebugInfo("div", v1, "/", v2, " == ", res)
		// note that here we don't ensure that divisor is != 0
		system.addConstraint(newR1C(v2, res, v1), debug)
		return res
	}

	// v2 is constant
	b2 := system.constantValue(v2)
	if b2.IsUint64() && b2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := system.curveID.Info().Fr.Modulus()
	b2.ModInverse(b2, q)

	if v1.IsConstant() {
		b2.Mul(b2, system.constantValue(v1)).Mod(b2, q)
		return system.constant(b2)
	}

	// v1 is not constant
	return system.mulConstant(v1, system.constant(b2).(compiled.Variable))
}

// Xor compute the XOR between two cs.Variables
func (system *R1CS) Xor(_a, _b cs.Variable) cs.Variable {

	vars, _ := system.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	// the formulation used is for easing up the conversion to sparse r1cs
	res := system.newInternalVariable()
	res.IsBoolean = new(bool)
	*res.IsBoolean = true
	c := system.Neg(res).(compiled.Variable)
	c.IsBoolean = new(bool)
	*c.IsBoolean = false
	c.LinExp = append(c.LinExp, a.LinExp[0], b.LinExp[0])
	aa := system.Mul(a, 2)
	system.constraints = append(system.constraints, newR1C(aa, b, c))

	return res
}

// Or compute the OR between two cs.Variables
func (system *R1CS) Or(_a, _b cs.Variable) cs.Variable {
	vars, _ := system.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	// the formulation used is for easing up the conversion to sparse r1cs
	res := system.newInternalVariable()
	res.IsBoolean = new(bool)
	*res.IsBoolean = true
	c := system.Neg(res).(compiled.Variable)
	c.IsBoolean = new(bool)
	*c.IsBoolean = false
	c.LinExp = append(c.LinExp, a.LinExp[0], b.LinExp[0])
	system.constraints = append(system.constraints, newR1C(a, b, c))

	return res
}

// And compute the AND between two cs.Variables
func (system *R1CS) And(_a, _b cs.Variable) cs.Variable {
	vars, _ := system.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	res := system.Mul(a, b)

	return res
}

// IsZero returns 1 if i1 is zero, 0 otherwise
func (system *R1CS) IsZero(i1 cs.Variable) cs.Variable {
	vars, _ := system.toVariables(i1)
	a := vars[0]
	if a.IsConstant() {
		// c := a.constantValue(cs)
		c := system.constantValue(a)
		if c.IsUint64() && c.Uint64() == 0 {
			return system.constant(1)
		}
		return system.constant(0)
	}

	debug := system.addDebugInfo("isZero", a)

	//m * (1 - m) = 0       // constrain m to be 0 or 1
	// a * m = 0            // constrain m to be 0 if a != 0
	// _ = inverse(m + a) 	// constrain m to be 1 if a == 0

	// m is computed by the solver such that m = 1 - a^(modulus - 1)
	m := system.NewHint(hint.IsZero, a)
	system.addConstraint(newR1C(a, m, system.constant(0)), debug)

	system.AssertIsBoolean(m)
	ma := system.Add(m, a)
	_ = system.Inverse(ma)
	return m

}

// ToBinary unpacks a cs.Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (system *R1CS) ToBinary(i1 cs.Variable, n ...int) []cs.Variable {

	// nbBits
	nbBits := system.bitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	vars, _ := system.toVariables(i1)
	a := vars[0]

	// if a is a constant, work with the big int value.
	if a.IsConstant() {
		c := system.constantValue(a)
		b := make([]compiled.Variable, nbBits)
		for i := 0; i < len(b); i++ {
			b[i] = system.constant(c.Bit(i)).(compiled.Variable)
		}
		return toSliceOfVariables(b)
	}

	return system.toBinary(a, nbBits, false)
}

// toBinary is equivalent to ToBinary, exept the returned bits are NOT boolean constrained.
func (system *R1CS) toBinary(a compiled.Variable, nbBits int, unsafe bool) []cs.Variable {

	if a.IsConstant() {
		return system.ToBinary(a, nbBits)
	}

	// ensure a is set
	a.AssertIsSet()

	// allocate the resulting cs.Variables and bit-constraint them
	b := make([]cs.Variable, nbBits)
	sb := make([]cs.Variable, nbBits)
	var c big.Int
	c.SetUint64(1)
	for i := 0; i < nbBits; i++ {
		b[i] = system.NewHint(hint.IthBit, a, i)
		sb[i] = system.Mul(b[i], c)
		c.Lsh(&c, 1)
		if !unsafe {
			system.AssertIsBoolean(b[i])
		}
	}

	//var Σbi compiled.Variable
	var Σbi cs.Variable
	if nbBits == 1 {
		system.AssertIsEqual(sb[0], a)
	} else if nbBits == 2 {
		Σbi = system.Add(sb[0], sb[1])
	} else {
		Σbi = system.Add(sb[0], sb[1], sb[2:]...)
	}
	system.AssertIsEqual(Σbi, a)

	// record the constraint Σ (2**i * b[i]) == a
	return b

}

func toSliceOfVariables(v []compiled.Variable) []cs.Variable {
	// TODO this is ugly.
	r := make([]cs.Variable, len(v))
	for i := 0; i < len(v); i++ {
		r[i] = v[i]
	}
	return r
}

// FromBinary packs b, seen as a fr.Element in little endian
func (system *R1CS) FromBinary(_b ...cs.Variable) cs.Variable {
	b, _ := system.toVariables(_b...)

	// ensure inputs are set
	for i := 0; i < len(b); i++ {
		b[i].AssertIsSet()
	}

	// res = Σ (2**i * b[i])

	var res, v cs.Variable
	res = system.constant(0) // no constraint is recorded

	var c big.Int
	c.SetUint64(1)

	L := make([]compiled.Term, len(b))
	for i := 0; i < len(L); i++ {
		v = system.Mul(c, b[i])      // no constraint is recorded
		res = system.Add(v, res)     // no constraint is recorded
		system.AssertIsBoolean(b[i]) // ensures the b[i]'s are boolean
		c.Lsh(&c, 1)
	}

	return res
}

// Select if i0 is true, yields i1 else yields i2
func (system *R1CS) Select(i0, i1, i2 cs.Variable) cs.Variable {

	vars, _ := system.toVariables(i0, i1, i2)
	b := vars[0]

	// ensures that b is boolean
	system.AssertIsBoolean(b)

	if vars[1].IsConstant() && vars[2].IsConstant() {
		n1 := system.constantValue(vars[1])
		n2 := system.constantValue(vars[2])
		diff := n1.Sub(n1, n2)
		res := system.Mul(b, diff)     // no constraint is recorded
		res = system.Add(res, vars[2]) // no constraint is recorded
		return res
	}

	// special case appearing in AssertIsLessOrEq
	if vars[1].IsConstant() {
		n1 := system.constantValue(vars[1])
		if n1.IsUint64() && n1.Uint64() == 0 {
			v := system.Sub(1, vars[0])
			return system.Mul(v, vars[2])
		}
	}

	v := system.Sub(vars[1], vars[2]) // no constraint is recorded
	w := system.Mul(b, v)
	return system.Add(w, vars[2])

}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (system *R1CS) Lookup2(b0, b1 cs.Variable, i0, i1, i2, i3 cs.Variable) cs.Variable {
	vars, _ := system.toVariables(b0, b1, i0, i1, i2, i3)
	s0, s1 := vars[0], vars[1]
	in0, in1, in2, in3 := vars[2], vars[3], vars[4], vars[5]

	// ensure that bits are actually bits. Adds no constraints if the variables
	// are already constrained.
	system.AssertIsBoolean(s0)
	system.AssertIsBoolean(s1)

	// two-bit lookup for the general case can be done with three constraints as
	// following:
	//    (1) (in3 - in2 - in1 + in0) * s1 = tmp1 - in1 + in0
	//    (2) tmp1 * s0 = tmp2
	//    (3) (in2 - in0) * s1 = RES - tmp2 - in0
	// the variables tmp1 and tmp2 are new internal variables and the variables
	// RES will be the returned result

	tmp1 := system.Add(in3, in0)
	tmp1 = system.Sub(tmp1, in2, in1)
	tmp1 = system.Mul(tmp1, s1)
	tmp1 = system.Add(tmp1, in1)
	tmp1 = system.Sub(tmp1, in0) // (1) tmp1 = s1 * (in3 - in2 - in1 + in0) + in1 - in0
	tmp2 := system.Mul(tmp1, s0) // (2) tmp2 = tmp1 * s0
	res := system.Sub(in2, in0)
	res = system.Mul(res, s1)
	res = system.Add(res, tmp2, in0) // (3) res = (v2 - v0) * s1 + tmp2 + in0
	return res
}

// IsConstant returns true if v is a constant known at compile time
func (system *R1CS) IsConstant(v cs.Variable) bool {
	if _v, ok := v.(compiled.Variable); ok {
		return _v.IsConstant()
	}
	// it's not a wire, it's another golang type, we consider it constant.
	// TODO we may want to use the struct parser to ensure this cs.Variable interface doesn't contain fields which are
	// cs.Variable
	return true
}

// ConstantValue returns the big.Int value of v.
// Will panic if v.IsConstant() == false
func (system *R1CS) ConstantValue(v cs.Variable) *big.Int {
	if _v, ok := v.(compiled.Variable); ok {
		return system.constantValue(_v)
	}
	r := FromInterface(v)
	return &r
}

// constant will return (and allocate if neccesary) a cs.Variable from given value
//
// if input is already a cs.Variable, does nothing
// else, attempts to convert input to a big.Int (see FromInterface) and returns a constant cs.Variable
//
// a constant cs.Variable does NOT necessary allocate a cs.Variable in the ConstraintSystem
// it is in the form ONE_WIRE * coeff
func (system *R1CS) constant(input cs.Variable) cs.Variable {

	switch t := input.(type) {
	case compiled.Variable:
		t.AssertIsSet()
		return t
	default:
		n := FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return system.one()
		}
		r := system.one()
		r.LinExp[0] = system.setCoeff(r.LinExp[0], &n)
		return r
	}
}

// toVariables return cs.Variable corresponding to inputs and the total size of the linear expressions
func (system *R1CS) toVariables(in ...cs.Variable) ([]compiled.Variable, int) {
	r := make([]compiled.Variable, 0, len(in))
	s := 0
	e := func(i cs.Variable) {
		v := system.constant(i).(compiled.Variable)
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
func (system *R1CS) negateLinExp(l []compiled.Term) []compiled.Term {
	res := make([]compiled.Term, len(l))
	var lambda big.Int
	for i, t := range l {
		cID, vID, visibility := t.Unpack()
		lambda.Neg(&system.coeffs[cID])
		cID = system.coeffID(&lambda)
		res[i] = compiled.Pack(vID, cID, visibility)
	}
	return res
}
