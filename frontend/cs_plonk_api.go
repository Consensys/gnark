/*
Copyright © 2021 ConsenSys Software Inc.

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

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// API represents the available functions to circuit developers

// Add returns res = i1+i2+...in
func (cs *plonkConstraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	zero := big.NewInt(0)
	vars, k := cs.filterConstant(append([]interface{}{i1, i2}, in...))
	if len(vars) == 0 {
		return k
	}
	if k.Cmp(zero) == 0 {
		return cs.split(vars[0], vars[1:])
	}
	cl, _, _ := vars[0].Unpack()
	kID := cs.coeffID(&k)
	res := cs.newInternalVariable()
	cs.newPlonkConstraint(vars[0], 0, res, cl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, kID)
	return cs.split(res, vars[1:])

}

// neg returns -in...
func (cs *plonkConstraintSystem) neg(in ...interface{}) []Variable {

	res := make([]Variable, len(in))

	for i := 0; i < len(in); i++ {
		res[i] = cs.Neg(in[i])
	}
	return res
}

// Sub returns res = i1 - i2 - ...in
func (cs *plonkConstraintSystem) Sub(i1, i2 interface{}, in ...interface{}) Variable {
	r := cs.neg(append([]interface{}{i2}, in...))
	return cs.Add(i1, r[0], r[1:])
}

// Neg returns -i
func (cs *plonkConstraintSystem) Neg(i1 interface{}) Variable {
	if cs.isConstant(i1) {
		k := cs.ConstantValue(i1)
		k.Neg(k)
		return *k
	} else {
		v := i1.(compiled.Term)
		c, _, _ := v.Unpack()
		coef := cs.coeffs[c]
		coef.Neg(&coef)
		c = cs.coeffID(&coef)
		v.SetCoeffID(c)
		return v
	}
}

// Mul returns res = i1 * i2 * ... in
func (cs *plonkConstraintSystem) Mul(i1, i2 interface{}, in ...interface{}) Variable {
	return 0
}

// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
func (cs *plonkConstraintSystem) DivUnchecked(i1, i2 interface{}) Variable {
	return 0
}

// Div returns i1 / i2
func (cs *plonkConstraintSystem) Div(i1, i2 interface{}) Variable {
	return 0
}

// Inverse returns res = 1 / i1
func (cs *plonkConstraintSystem) Inverse(i1 interface{}) Variable {
	return 0
}

// ---------------------------------------------------------------------------------------------
// Bit operations

// ToBinary unpacks a Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (cs *plonkConstraintSystem) ToBinary(i1 interface{}, n ...int) []Variable {
	return []Variable{}
}

// FromBinary packs b, seen as a fr.Element in little endian
func (cs *plonkConstraintSystem) FromBinary(b ...interface{}) Variable {
	return 0
}

// Xor returns a ^ b
// a and b must be 0 or 1
func (cs *plonkConstraintSystem) Xor(a, b Variable) Variable {
	return 0
}

// Or returns a | b
// a and b must be 0 or 1
func (cs *plonkConstraintSystem) Or(a, b Variable) Variable {
	return 0
}

// Or returns a & b
// a and b must be 0 or 1
func (cs *plonkConstraintSystem) And(a, b Variable) Variable {
	return 0
}

// ---------------------------------------------------------------------------------------------
// Conditionals

// Select if b is true, yields i1 else yields i2
func (cs *plonkConstraintSystem) Select(b interface{}, i1, i2 interface{}) Variable {
	return 0
}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (cs *plonkConstraintSystem) Lookup2(b0, b1 interface{}, i0, i1, i2, i3 interface{}) Variable {
	return 0
}

// IsZero returns 1 if a is zero, 0 otherwise
func (cs *plonkConstraintSystem) IsZero(i1 interface{}) Variable {
	return 0
}

// ---------------------------------------------------------------------------------------------
// Assertions

// AssertIsEqual fails if i1 != i2
func (cs *plonkConstraintSystem) AssertIsEqual(i1, i2 interface{}) {
}

// AssertIsDifferent fails if i1 == i2
func (cs *plonkConstraintSystem) AssertIsDifferent(i1, i2 interface{}) {
}

// AssertIsBoolean fails if v != 0 || v != 1
func (cs *plonkConstraintSystem) AssertIsBoolean(i1 interface{}) {
}

// AssertIsLessOrEqual fails if  v > bound
func (cs *plonkConstraintSystem) AssertIsLessOrEqual(v Variable, bound interface{}) {
}

// Println behaves like fmt.Println but accepts frontend.Variable as parameter
// whose value will be resolved at runtime when computed by the solver
func (cs *plonkConstraintSystem) Println(a ...interface{}) {
}

// NewHint initializes an internal variable whose value will be evaluated
// using the provided hint function at run time from the inputs. Inputs must
// be either variables or convertible to *big.Int.
//
// The hint function is provided at the proof creation time and is not
// embedded into the circuit. From the backend point of view, the variable
// returned by the hint function is equivalent to the user-supplied witness,
// but its actual value is assigned by the solver, not the caller.
//
// No new constraints are added to the newly created wire and must be added
// manually in the circuit. Failing to do so leads to solver failure.
func (cs *plonkConstraintSystem) NewHint(f hint.Function, inputs ...interface{}) Variable {
	return 0
}

// Tag creates a tag at a given place in a circuit. The state of the tag may contain informations needed to
// measure constraints, variables and coefficients creations through AddCounter
func (cs *plonkConstraintSystem) Tag(name string) Tag {
	return Tag{}
}

// AddCounter measures the number of constraints, variables and coefficients created between two tags
// note that the PlonK statistics are contextual since there is a post-compile phase where linear expressions
// are factorized. That is, measuring 2 times the "repeating" piece of circuit may give less constraints the second time
func (cs *plonkConstraintSystem) AddCounter(from, to Tag) {
}

// IsConstant returns true if v is a constant known at compile time
func (cs *plonkConstraintSystem) IsConstant(v Variable) bool {
	return true
}

// ConstantValue returns the big.Int value of v. It
// panics if v.IsConstant() == false
func (cs *plonkConstraintSystem) ConstantValue(v Variable) *big.Int {
	if !cs.isConstant(v) {
		panic("v should be a constant")
	}
	res := FromInterface(v)
	return &res
}

// CurveID returns the ecc.ID injected by the compiler
func (cs *plonkConstraintSystem) CurveID() ecc.ID {
	return cs.curveID
}

// Backend returns the backend.ID injected by the compiler
func (cs *plonkConstraintSystem) Backend() backend.ID {
	return cs.backendID
}

// returns in split in a slice of compiledTerm and the sum of all constants in in as a bigInt
func (cs *plonkConstraintSystem) filterConstant(in ...interface{}) ([]compiled.Term, big.Int) {
	res := make([]compiled.Term, 0, len(in))
	var b big.Int
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			res = append(res, t)
		default:
			n := FromInterface(t)
			b.Add(&b, &n)
		}
	}
	return res, b
}

// computes the sum of the constant in in... and returns it as a bigInt
func (cs *plonkConstraintSystem) sum(in ...interface{}) big.Int {
	var res big.Int
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			continue
		default:
			n := FromInterface(t)
			res.Add(&res, &n)
		}
	}
	return res
}

// returns true the argument is a constant, false otherwise
func (cs *plonkConstraintSystem) isConstant(i interface{}) bool {
	switch t := i.(type) {
	case compiled.Term:
		return false
	default:
		FromInterface(t)
		return true
	}
}

func (cs *plonkConstraintSystem) split(acc compiled.Term, r []compiled.Term) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := cs.newInternalVariable()
	cs.newPlonkConstraint(acc, r[0], o, cl, cr, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return cs.split(o, r[1:])
}
