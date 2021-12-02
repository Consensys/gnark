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
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// API represents the available functions to circuit developers

// Add returns res = i1+i2+...in
func (cs *plonkConstraintSystem) Add(i1, i2 interface{}, in ...interface{}) Variable {

	zero := big.NewInt(0)
	vars, k := cs.filterConstantSum(append([]interface{}{i1, i2}, in...))
	if len(vars) == 0 {
		return k
	}
	if k.Cmp(zero) == 0 {
		return cs.splitSum(vars[0], vars[1:])
	}
	cl, _, _ := vars[0].Unpack()
	kID := cs.coeffID(&k)
	o := cs.newInternalVariable()
	cs.addPlonkConstraint(vars[0], 0, o, cl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, kID)
	return cs.splitSum(o, vars[1:])

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
	if cs.IsConstant(i1) {
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

	zero := big.NewInt(0)

	vars, k := cs.filterConstantProd(append([]interface{}{i1, i2}, in...))
	if len(vars) == 0 {
		return k
	}
	if k.Cmp(zero) == 0 {
		return cs.splitProd(vars[0], vars[1:])
	}
	l := cs.mulConstant(vars[0], &k)
	return cs.splitProd(l, vars[1:])

}

// returns t*m
func (cs *plonkConstraintSystem) mulConstant(t compiled.Term, m *big.Int) compiled.Term {
	cid, _, _ := t.Unpack()
	coef := cs.coeffs[cid]
	coef.Mul(m, &coef).Mod(&coef, cs.curveID.Info().Fr.Modulus())
	cid = cs.coeffID(&coef)
	t.SetCoeffID(cid)
	return t
}

// returns t/m
func (cs *plonkConstraintSystem) divConstant(t compiled.Term, m *big.Int) compiled.Term {
	cid, _, _ := t.Unpack()
	coef := cs.coeffs[cid]
	var _m big.Int
	q := cs.curveID.Info().Fr.Modulus()
	_m.Set(m).
		ModInverse(&_m, q).
		Mul(&_m, &coef).
		Mod(&_m, q)
	cid = cs.coeffID(&coef)
	t.SetCoeffID(cid)
	return t
}

// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
func (cs *plonkConstraintSystem) DivUnchecked(i1, i2 interface{}) Variable {
	if cs.IsConstant(i1) && cs.IsConstant(i2) {
		l := FromInterface(i1)
		r := FromInterface(i2)
		q := cs.curveID.Info().Fr.Modulus()
		return r.ModInverse(&r, q).
			Mul(&l, &r).
			Mod(&l, q)
	}
	if cs.IsConstant(i2) {
		c := FromInterface(i2)
		t := i1.(compiled.Term)
		return cs.divConstant(t, &c)
	}
	if cs.IsConstant(i1) {
		t := i2.(compiled.Term)
		cidr, _, _ := t.Unpack()
		res := cs.newInternalVariable()
		c := FromInterface(i1)
		cidl := cs.coeffID(&c)
		cs.addPlonkConstraint(res, t, 0, compiled.CoeffIdZero, compiled.CoeffIdZero, cidl, cidr, compiled.CoeffIdZero, compiled.CoeffIdMinusOne)
		return res
	}
	res := cs.newInternalVariable()
	t1 := i1.(compiled.Term)
	t2 := i2.(compiled.Term)
	cl, _, _ := t1.Unpack()
	cr, _, _ := t2.Unpack()
	cs.addPlonkConstraint(t1, t2, 0, compiled.CoeffIdZero, compiled.CoeffIdZero, cl, cr, compiled.CoeffIdZero, compiled.CoeffIdMinusOne)
	return res
}

// Div returns i1 / i2
func (cs *plonkConstraintSystem) Div(i1, i2 interface{}) Variable {
	// TODO check that later
	return cs.DivUnchecked(i1, i2)
}

// Inverse returns res = 1 / i1
func (cs *plonkConstraintSystem) Inverse(i1 interface{}) Variable {
	if cs.IsConstant(i1) {
		c := FromInterface(i1)
		c.ModInverse(&c, cs.CurveID().Info().Fr.Modulus())
		return c
	}
	t := i1.(compiled.Term)
	cr, _, _ := t.Unpack()
	res := cs.newInternalVariable()
	cs.addPlonkConstraint(res, t, 0, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, cr, compiled.CoeffIdZero, compiled.CoeffIdMinusOne)
	return res
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
	_b := make([]Variable, len(b))
	var c big.Int
	c.SetUint64(1)
	for i := 0; i < len(b); i++ {
		_b[0] = cs.Mul(b[i], c)
		c.Lsh(&c, 1)
	}
	if len(b) == 1 {
		return b[0]
	}
	if len(b) == 1 {
		return cs.Add(_b[0], _b[1])
	}
	return cs.Add(_b[0], _b[1], _b[2:])
}

// Xor returns a ^ b
// a and b must be 0 or 1
func (cs *plonkConstraintSystem) Xor(a, b Variable) Variable {
	if cs.IsConstant(a) && cs.IsConstant(b) {
		_a := FromInterface(a)
		_b := FromInterface(b)
		_a.Xor(&_a, &_b)
		return _a
	}
	res := cs.newInternalVariable()
	if cs.IsConstant(a) {
		a, b = b, a
	}
	if cs.IsConstant(b) {
		l := a.(compiled.Term)
		r := l
		_b := FromInterface(b)
		one := big.NewInt(1)
		_b.Lsh(&_b, 1).Sub(&_b, one)
		idl := cs.coeffID(&_b)
		cs.addPlonkConstraint(l, r, res, idl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero)
		return res
	}
	l := a.(compiled.Term)
	r := b.(compiled.Term)
	cs.addPlonkConstraint(l, r, res, compiled.CoeffIdMinusOne, compiled.CoeffIdMinusOne, compiled.CoeffIdTwo, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero)
	return res
}

// Or returns a | b
// a and b must be 0 or 1
func (cs *plonkConstraintSystem) Or(a, b Variable) Variable {
	if cs.IsConstant(a) && cs.IsConstant(b) {
		_a := FromInterface(a)
		_b := FromInterface(b)
		_a.Or(&_a, &_b)
		return _a
	}
	res := cs.newInternalVariable()
	if cs.IsConstant(a) {
		a, b = b, a
	}
	if cs.IsConstant(b) {
		l := a.(compiled.Term)
		r := l
		_b := FromInterface(b)
		one := big.NewInt(1)
		_b.Sub(&_b, one)
		idl := cs.coeffID(&_b)
		cs.addPlonkConstraint(l, r, res, idl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero)
		return res
	}
	l := a.(compiled.Term)
	r := b.(compiled.Term)
	cs.addPlonkConstraint(l, r, res, compiled.CoeffIdMinusOne, compiled.CoeffIdMinusOne, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero)
	return res
}

// Or returns a & b
// a and b must be 0 or 1
func (cs *plonkConstraintSystem) And(a, b Variable) Variable {
	return cs.Mul(a, b)
}

// ---------------------------------------------------------------------------------------------
// Conditionals

// Select if b is true, yields i1 else yields i2
func (cs *plonkConstraintSystem) Select(b interface{}, i1, i2 interface{}) Variable {

	if cs.IsConstant(b) {
		_b := FromInterface(b)
		var t big.Int
		one := big.NewInt(1)
		if _b.Cmp(&t) != 0 && _b.Cmp(one) != 0 {
			panic("b should be a boolean")
		}
		if _b.Cmp(&t) == 0 {
			return i2
		}
		return i1
	}

	u := cs.Sub(i2, i1)
	l := cs.Mul(u, b)
	res := cs.newInternalVariable()
	if cs.IsConstant(i2) {
		k := FromInterface(i2)
		_k := cs.coeffID(&k)
		cs.addPlonkConstraint(l, 0, res, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, _k)
	} else {
		_r := i2.(compiled.Term)
		cs.addPlonkConstraint(l, _r, res, compiled.CoeffIdOne, compiled.CoeffIdMinusOne, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero)
	}
	return res
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

	if cs.IsConstant(i1) && cs.IsConstant(i2) {
		a := FromInterface(i1)
		b := FromInterface(i2)
		if a.Cmp(&b) != 0 {
			panic("i1, i2 should be equal")
		}
	}
	if cs.IsConstant(i1) {
		i1, i2 = i2, i1
	}
	if cs.IsConstant(i2) {
		l := i1.(compiled.Term)
		k := FromInterface(i2)
		debug := cs.addDebugInfo("assertIsEqual", l, " == ", k)
		k.Neg(&k)
		_k := cs.coeffID(&k)
		cs.addPlonkConstraint(l, 0, 0, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, _k, debug)
	}
	l := i1.(compiled.Term)
	r := i1.(compiled.Term)
	debug := cs.addDebugInfo("assertIsEqual", l, " == ", r)
	cs.addPlonkConstraint(l, 0, r, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero, debug)
}

// AssertIsDifferent fails if i1 == i2
func (cs *plonkConstraintSystem) AssertIsDifferent(i1, i2 interface{}) {
}

// AssertIsBoolean fails if v != 0 || v != 1
func (cs *plonkConstraintSystem) AssertIsBoolean(i1 interface{}) {
	if cs.IsConstant(i1) {
		c := FromInterface(i1)
		if !(c.IsUint64() && (c.Uint64() == 0 || c.Uint64() == 1)) {
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", c.String()))
		}
		return
	}
	t := i1.(compiled.Term)
	debug := cs.addDebugInfo("assertIsBoolean", t, " == (0|1)")
	cs.addPlonkConstraint(t, t, 0, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, debug)
}

// AssertIsLessOrEqual fails if  v > bound
func (cs *plonkConstraintSystem) AssertIsLessOrEqual(v Variable, bound interface{}) {
}

// Println behaves like fmt.Println but accepts frontend.Variable as parameter
// whose value will be resolved at runtime when computed by the solver
// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a variable, its value will be resolved avec R1CS.Solve() method is called
func (cs *plonkConstraintSystem) Println(a ...interface{}) {
	var sbb strings.Builder

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	var log compiled.LogEntry

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		if v, ok := arg.(compiled.Variable); ok {
			v.AssertIsSet()

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
			log.ToResolve = append(log.ToResolve, v.LinExp...)
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		} else {
			printArg(&log, &sbb, arg)
		}
	}
	sbb.WriteByte('\n')

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	log.Format = sbb.String()

	cs.logs = append(cs.logs, log)
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
	_, file, line, _ := runtime.Caller(1)

	return Tag{
		Name: fmt.Sprintf("%s[%s:%d]", name, filepath.Base(file), line),
		vID:  cs.internal,
		cID:  len(cs.constraints),
	}
}

// AddCounter measures the number of constraints, variables and coefficients created between two tags
// note that the PlonK statistics are contextual since there is a post-compile phase where linear expressions
// are factorized. That is, measuring 2 times the "repeating" piece of circuit may give less constraints the second time
func (cs *plonkConstraintSystem) AddCounter(from, to Tag) {
	cs.counters = append(cs.counters, Counter{
		From:          from,
		To:            to,
		NbVariables:   to.vID - from.vID,
		NbConstraints: to.cID - from.cID,
	})
}

// IsConstant returns true if v is a constant known at compile time
func (cs *plonkConstraintSystem) IsConstant(v Variable) bool {
	switch t := v.(type) {
	case compiled.Term:
		return false
	default:
		FromInterface(t)
		return true
	}
}

// ConstantValue returns the big.Int value of v. It
// panics if v.IsConstant() == false
func (cs *plonkConstraintSystem) ConstantValue(v Variable) *big.Int {
	if !cs.IsConstant(v) {
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

// returns in split into a slice of compiledTerm and the sum of all constants in in as a bigInt
func (cs *plonkConstraintSystem) filterConstantSum(in ...interface{}) ([]compiled.Term, big.Int) {
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

// returns in split into a slice of compiledTerm and the product of all constants in in as a bigInt
func (cs *plonkConstraintSystem) filterConstantProd(in ...interface{}) ([]compiled.Term, big.Int) {
	res := make([]compiled.Term, 0, len(in))
	var b big.Int
	b.SetInt64(1)
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			res = append(res, t)
		default:
			n := FromInterface(t)
			b.Mul(&b, &n)
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

func (cs *plonkConstraintSystem) splitSum(acc compiled.Term, r []compiled.Term) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := cs.newInternalVariable()
	cs.addPlonkConstraint(acc, r[0], o, cl, cr, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return cs.splitSum(o, r[1:])
}

func (cs *plonkConstraintSystem) splitProd(acc compiled.Term, r []compiled.Term) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := cs.newInternalVariable()
	cs.addPlonkConstraint(acc, r[0], o, compiled.CoeffIdZero, compiled.CoeffIdZero, cl, cr, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return cs.splitProd(o, r[1:])
}
