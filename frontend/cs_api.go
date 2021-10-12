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
func (cs *ConstraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	var res Variable
	res.linExp = make(compiled.LinearExpression, 0, 2+len(in))

	add := func(_i interface{}) {
		switch t := _i.(type) {
		case Variable:
			t.assertIsSet() // always call this in case of a dangling variable, otherwise compile will not recognize Unset variables
			res.linExp = append(res.linExp, t.linExp.Clone()...)
		default:
			v := cs.Constant(t)
			res.linExp = append(res.linExp, v.linExp.Clone()...)
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

// Neg returns -i
func (cs *ConstraintSystem) Neg(i interface{}) Variable {

	var res Variable

	switch t := i.(type) {
	case Variable:
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
func (cs *ConstraintSystem) negateLinExp(l compiled.LinearExpression) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(l))
	var coeff, coeffCopy big.Int
	for i, t := range l {
		coeffID, variableID, constraintVis := t.Unpack()
		coeff = cs.coeffs[coeffID]
		coeffCopy.Neg(&coeff)
		res[i] = cs.makeTerm(Wire{constraintVis, variableID, nil}, &coeffCopy)
	}
	return res
}

// Sub returns res = i1 - i2
func (cs *ConstraintSystem) Sub(i1, i2 interface{}) Variable {

	var res Variable
	res.linExp = make(compiled.LinearExpression, 0, 2)

	switch t := i1.(type) {
	case Variable:
		t.assertIsSet()
		res.linExp = t.linExp.Clone()
	default:
		v := cs.Constant(t)
		res.linExp = v.linExp.Clone()
	}

	switch t := i2.(type) {
	case Variable:
		t.assertIsSet()
		negLinExp := cs.negateLinExp(t.linExp)
		res.linExp = append(res.linExp, negLinExp...)
	default:
		v := cs.Constant(t)
		negLinExp := cs.negateLinExp(v.linExp)
		res.linExp = append(res.linExp, negLinExp...)
	}

	res.linExp = cs.reduce(res.linExp)

	return res
}

func (cs *ConstraintSystem) mulConstant(i interface{}, v Variable) Variable {
	var linExp compiled.LinearExpression
	var newCoeff big.Int

	lambda := FromInterface(i)

	for _, t := range v.linExp {
		cID, vID, visibility := t.Unpack()
		switch cID {
		case compiled.CoeffIdMinusOne:
			newCoeff.Neg(&lambda)
		case compiled.CoeffIdZero:
			newCoeff.SetUint64(0)
		case compiled.CoeffIdOne:
			newCoeff.Set(&lambda)
		case compiled.CoeffIdTwo:
			newCoeff.Add(&lambda, &lambda)
		default:
			coeff := cs.coeffs[cID]
			newCoeff.Mul(&coeff, &lambda)
		}
		linExp = append(linExp, cs.makeTerm(Wire{visibility, vID, nil}, &newCoeff))
	}
	return Variable{Wire{}, linExp}
}

// Mul returns res = i1 * i2 * ... in
func (cs *ConstraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {

	mul := func(_i1, _i2 interface{}) Variable {
		var _res Variable
		switch t1 := _i1.(type) {
		case Variable:
			t1.assertIsSet()
			switch t2 := _i2.(type) {
			case Variable:
				t2.assertIsSet()
				_res = cs.newInternalVariable() // only in this case we record the constraint in the cs
				cs.constraints = append(cs.constraints, newR1C(t1, t2, _res))
				return _res
			default:
				_res = cs.mulConstant(t2, t1)
				return _res
			}
		default:
			switch t2 := _i2.(type) {
			case Variable:
				t2.assertIsSet()
				_res = cs.mulConstant(t1, t2)
				return _res
			default:
				n1 := FromInterface(t1)
				n2 := FromInterface(t2)
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
func (cs *ConstraintSystem) Inverse(v Variable) Variable {
	v.assertIsSet()

	// allocate resulting variable
	res := cs.newInternalVariable()

	debug := cs.addDebugInfo("inverse", v, "*", res, " == 1")

	cs.addConstraint(newR1C(v, res, cs.one()), debug)

	return res
}

// Div returns res = i1 / i2
func (cs *ConstraintSystem) Div(i1, i2 interface{}) Variable {
	// allocate resulting variable
	res := cs.newInternalVariable()

	v1 := cs.Constant(i1)
	v2 := cs.Constant(i2)

	debug := cs.addDebugInfo("div", v1, "/", v2, " == ", res)

	cs.addConstraint(newR1C(v2, res, v1), debug)

	return res
}

// Xor compute the XOR between two variables
func (cs *ConstraintSystem) Xor(a, b Variable) Variable {

	a.assertIsSet()
	b.assertIsSet()

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
func (cs *ConstraintSystem) Or(a, b Variable) Variable {

	a.assertIsSet()
	b.assertIsSet()

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.newInternalVariable()
	v1 := cs.Sub(1, a)
	v2 := cs.Sub(res, a)

	cs.constraints = append(cs.constraints, newR1C(b, v1, v2))

	return res
}

// And compute the AND between two variables
func (cs *ConstraintSystem) And(a, b Variable) Variable {

	a.assertIsSet()
	b.assertIsSet()

	cs.AssertIsBoolean(a)
	cs.AssertIsBoolean(b)

	res := cs.Mul(a, b)

	return res
}

// IsZero returns 1 if a is zero, 0 otherwise
func (cs *ConstraintSystem) IsZero(a Variable) Variable {
	a.assertIsSet()
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
func (cs *ConstraintSystem) ToBinary(a Variable, n ...int) []Variable {
	// ensure a is set
	a.assertIsSet()

	nbBits := cs.bitLen()
	if len(n) == 1 {
		nbBits = n[0]
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
		Σbi.linExp[i] = cs.makeTerm(Wire{compiled.Internal, b[i].id, nil}, &c)
		c.Lsh(&c, 1)
	}

	// record the constraint Σ (2**i * b[i]) == a
	cs.constraints = append(cs.constraints, newR1C(Σbi, cs.one(), a))
	return b

}

// toBinaryUnsafe is equivalent to ToBinary, exept the returned bits are NOT boolean constrained.
func (cs *ConstraintSystem) toBinaryUnsafe(a Variable, nbBits int) []Variable {
	// ensure a is set
	a.assertIsSet()

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
		Σbi.linExp[i] = cs.makeTerm(Wire{compiled.Internal, b[i].id, nil}, &c)
		c.Lsh(&c, 1)
	}

	// record the constraint Σ (2**i * b[i]) == a
	cs.constraints = append(cs.constraints, newR1C(Σbi, cs.one(), a))
	return b

}

// FromBinary packs b, seen as a fr.Element in little endian
func (cs *ConstraintSystem) FromBinary(b ...Variable) Variable {
	// ensure inputs are set
	for i := 0; i < len(b); i++ {
		b[i].assertIsSet()
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
func (cs *ConstraintSystem) Select(b Variable, i1, i2 interface{}) Variable {

	b.assertIsSet()

	// ensures that b is boolean
	cs.AssertIsBoolean(b)

	var res Variable

	switch t1 := i1.(type) {
	case Variable:
		t1.assertIsSet()
		res = cs.newInternalVariable()
		v := cs.Sub(t1, i2)  // no constraint is recorded
		w := cs.Sub(res, i2) // no constraint is recorded
		//cs.Println("u-v: ", v)
		cs.constraints = append(cs.constraints, newR1C(v, b, w))
		return res
	default:
		switch t2 := i2.(type) {
		case Variable:
			t2.assertIsSet()
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

// Constant will return (and allocate if neccesary) a constant Variable
//
// input can be a Variable or must be convertible to big.Int (see FromInterface)
func (cs *ConstraintSystem) Constant(input interface{}) Variable {

	switch t := input.(type) {
	case Variable:
		t.assertIsSet()
		return t
	default:
		n := FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return cs.one()
		}
		// cs.mulConstant(n, cs.one())
		return Variable{Wire{}, compiled.LinearExpression{
			cs.makeTerm(Wire{compiled.Public, 0, nil}, &n),
		}}
	}
}
