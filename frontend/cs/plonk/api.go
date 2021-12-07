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

package plonk

import (
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/utils"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// Add returns res = i1+i2+...in
func (system *SparseR1CS) Add(i1, i2 cs.Variable, in ...cs.Variable) cs.Variable {
	zero := big.NewInt(0)
	vars, k := system.filterConstantSum(append([]cs.Variable{i1, i2}, in...))

	if len(vars) == 0 {
		return k
	}
	vars = system.reduce(vars)
	if k.Cmp(zero) == 0 {
		return system.splitSum(vars[0], vars[1:])
	}
	cl, _, _ := vars[0].Unpack()
	kID := system.CoeffID(&k)
	o := system.newInternalVariable()
	system.addPlonkConstraint(vars[0], system.zero(), o, cl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, kID)
	return system.splitSum(o, vars[1:])

}

// neg returns -in
func (system *SparseR1CS) neg(in []cs.Variable) []cs.Variable {

	res := make([]cs.Variable, len(in))

	for i := 0; i < len(in); i++ {
		res[i] = system.Neg(in[i])
	}
	return res
}

// Sub returns res = i1 - i2 - ...in
func (system *SparseR1CS) Sub(i1, i2 cs.Variable, in ...cs.Variable) cs.Variable {
	r := system.neg(append([]cs.Variable{i2}, in...))
	return system.Add(i1, r[0], r[1:]...)
}

// Neg returns -i
func (system *SparseR1CS) Neg(i1 cs.Variable) cs.Variable {
	if system.IsConstant(i1) {
		k := system.ConstantValue(i1)
		k.Neg(k)
		return *k
	} else {
		v := i1.(compiled.Term)
		c, _, _ := v.Unpack()
		coef := system.Coeffs[c]
		coef.Neg(&coef)
		c = system.CoeffID(&coef)
		v.SetCoeffID(c)
		return v
	}
}

// Mul returns res = i1 * i2 * ... in
func (system *SparseR1CS) Mul(i1, i2 cs.Variable, in ...cs.Variable) cs.Variable {

	zero := big.NewInt(0)

	vars, k := system.filterConstantProd(append([]cs.Variable{i1, i2}, in...))
	if len(vars) == 0 {
		return k
	}
	if k.Cmp(zero) == 0 {
		return system.splitProd(vars[0], vars[1:])
	}
	l := system.mulConstant(vars[0], &k)
	return system.splitProd(l, vars[1:])

}

// returns t*m
func (system *SparseR1CS) mulConstant(t compiled.Term, m *big.Int) compiled.Term {
	cid, _, _ := t.Unpack()
	coef := system.Coeffs[cid]
	coef.Mul(m, &coef).Mod(&coef, system.CurveID.Info().Fr.Modulus())
	cid = system.CoeffID(&coef)
	t.SetCoeffID(cid)
	return t
}

// returns t/m
func (system *SparseR1CS) divConstant(t compiled.Term, m *big.Int) compiled.Term {
	cid, _, _ := t.Unpack()
	coef := system.Coeffs[cid]
	var _m big.Int
	q := system.CurveID.Info().Fr.Modulus()
	_m.Set(m).
		ModInverse(&_m, q).
		Mul(&_m, &coef).
		Mod(&_m, q)
	cid = system.CoeffID(&coef)
	t.SetCoeffID(cid)
	return t
}

// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
func (system *SparseR1CS) DivUnchecked(i1, i2 cs.Variable) cs.Variable {

	if system.IsConstant(i1) && system.IsConstant(i2) {
		l := utils.FromInterface(i1)
		r := utils.FromInterface(i2)
		q := system.CurveID.Info().Fr.Modulus()
		return r.ModInverse(&r, q).
			Mul(&l, &r).
			Mod(&l, q)
	}
	if system.IsConstant(i2) {
		c := utils.FromInterface(i2)
		t := i1.(compiled.Term)
		return system.divConstant(t, &c)
	}
	if system.IsConstant(i1) {
		t := i2.(compiled.Term)
		cidr, _, _ := t.Unpack()
		res := system.newInternalVariable()
		c := utils.FromInterface(i1)
		cidl := system.CoeffID(&c)
		system.addPlonkConstraint(res, t, system.zero(), compiled.CoeffIdZero, compiled.CoeffIdZero, cidl, cidr, compiled.CoeffIdZero, compiled.CoeffIdMinusOne)
		return res
	}
	res := system.newInternalVariable()
	r := i2.(compiled.Term)
	o := system.Neg(i1).(compiled.Term)
	cr, _, _ := r.Unpack()
	co, _, _ := o.Unpack()
	system.addPlonkConstraint(res, r, o, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, cr, co, compiled.CoeffIdZero)
	return res
}

// Div returns i1 / i2
func (system *SparseR1CS) Div(i1, i2 cs.Variable) cs.Variable {
	// TODO check that later
	return system.DivUnchecked(i1, i2)
}

// Inverse returns res = 1 / i1
func (system *SparseR1CS) Inverse(i1 cs.Variable) cs.Variable {
	if system.IsConstant(i1) {
		c := utils.FromInterface(i1)
		c.ModInverse(&c, system.CurveID.Info().Fr.Modulus())
		return c
	}
	t := i1.(compiled.Term)
	cr, _, _ := t.Unpack()
	res := system.newInternalVariable()
	system.addPlonkConstraint(res, t, system.zero(), compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, cr, compiled.CoeffIdZero, compiled.CoeffIdMinusOne)
	return res
}

// ---------------------------------------------------------------------------------------------
// Bit operations

// ToBinary unpacks a cs.Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (system *SparseR1CS) ToBinary(i1 cs.Variable, n ...int) []cs.Variable {

	// nbBits
	nbBits := system.BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	// if a is a constant, work with the big int value.
	if system.IsConstant(i1) {
		c := utils.FromInterface(i1)
		b := make([]cs.Variable, nbBits)
		for i := 0; i < len(b); i++ {
			b[i] = c.Bit(i)
		}
		return b
	}

	a := i1.(compiled.Term)
	return system.toBinary(a, nbBits, false)
}

func (system *SparseR1CS) toBinary(a compiled.Term, nbBits int, unsafe bool) []cs.Variable {

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

	//var Σbi compiled.Term
	// TODO we can save a constraint here
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

// FromBinary packs b, seen as a fr.Element in little endian
func (system *SparseR1CS) FromBinary(b ...cs.Variable) cs.Variable {
	_b := make([]cs.Variable, len(b))
	var c big.Int
	c.SetUint64(1)
	for i := 0; i < len(b); i++ {
		_b[i] = system.Mul(b[i], c)
		c.Lsh(&c, 1)
	}
	if len(b) == 1 {
		return b[0]
	}
	if len(b) == 1 {
		return system.Add(_b[0], _b[1])
	}
	return system.Add(_b[0], _b[1], _b[2:]...)
}

// Xor returns a ^ b
// a and b must be 0 or 1
func (system *SparseR1CS) Xor(a, b cs.Variable) cs.Variable {
	if system.IsConstant(a) && system.IsConstant(b) {
		_a := utils.FromInterface(a)
		_b := utils.FromInterface(b)
		_a.Xor(&_a, &_b)
		return _a
	}
	res := system.newInternalVariable()
	if system.IsConstant(a) {
		a, b = b, a
	}
	if system.IsConstant(b) {
		l := a.(compiled.Term)
		r := l
		_b := utils.FromInterface(b)
		one := big.NewInt(1)
		_b.Lsh(&_b, 1).Sub(&_b, one)
		idl := system.CoeffID(&_b)
		system.addPlonkConstraint(l, r, res, idl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero)
		return res
	}
	l := a.(compiled.Term)
	r := b.(compiled.Term)
	system.addPlonkConstraint(l, r, res, compiled.CoeffIdMinusOne, compiled.CoeffIdMinusOne, compiled.CoeffIdTwo, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero)
	return res
}

// Or returns a | b
// a and b must be 0 or 1
func (system *SparseR1CS) Or(a, b cs.Variable) cs.Variable {
	if system.IsConstant(a) && system.IsConstant(b) {
		_a := utils.FromInterface(a)
		_b := utils.FromInterface(b)
		_a.Or(&_a, &_b)
		return _a
	}
	res := system.newInternalVariable()
	if system.IsConstant(a) {
		a, b = b, a
	}
	if system.IsConstant(b) {
		l := a.(compiled.Term)
		r := l
		_b := utils.FromInterface(b)
		one := big.NewInt(1)
		_b.Sub(&_b, one)
		idl := system.CoeffID(&_b)
		system.addPlonkConstraint(l, r, res, idl, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero)
		return res
	}
	l := a.(compiled.Term)
	r := b.(compiled.Term)
	system.addPlonkConstraint(l, r, res, compiled.CoeffIdMinusOne, compiled.CoeffIdMinusOne, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero)
	return res
}

// Or returns a & b
// a and b must be 0 or 1
func (system *SparseR1CS) And(a, b cs.Variable) cs.Variable {
	return system.Mul(a, b)
}

// ---------------------------------------------------------------------------------------------
// Conditionals

// Select if b is true, yields i1 else yields i2
func (system *SparseR1CS) Select(b cs.Variable, i1, i2 cs.Variable) cs.Variable {

	if system.IsConstant(b) {
		_b := utils.FromInterface(b)
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

	u := system.Sub(i1, i2)
	l := system.Mul(u, b)

	return system.Add(l, i2)
}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (system *SparseR1CS) Lookup2(b0, b1 cs.Variable, i0, i1, i2, i3 cs.Variable) cs.Variable {
	return 0
}

// IsZero returns 1 if a is zero, 0 otherwise
func (system *SparseR1CS) IsZero(i1 cs.Variable) cs.Variable {

	if system.IsConstant(i1) {
		a := utils.FromInterface(i1)
		var zero big.Int
		if a.Cmp(&zero) != 0 {
			panic("input should be zero")
		}
		return 1
	}

	a := i1.(compiled.Term)
	m := system.NewHint(hint.IsZero, a)
	system.AssertIsBoolean(i1)
	system.addPlonkConstraint(a, m.(compiled.Term), system.zero(), compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero)
	ma := system.Add(m, a)
	system.Inverse(ma)
	return m
}

// Println behaves like fmt.Println but accepts Variable as parameter
// whose value will be resolved at runtime when computed by the solver
// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a variable, its value will be resolved avec R1CS.Solve() method is called
func (system *SparseR1CS) Println(a ...cs.Variable) {
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
		if v, ok := arg.(compiled.Term); ok {

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
			log.ToResolve = append(log.ToResolve, v)
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		} else {
			printArg(&log, &sbb, arg)
		}
	}
	sbb.WriteByte('\n')

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	log.Format = sbb.String()

	system.Logs = append(system.Logs, log)
}

func printArg(log *compiled.LogEntry, sbb *strings.Builder, a cs.Variable) {

	count := 0
	counter := func(visibility compiled.Visibility, name string, tValue reflect.Value) error {
		count++
		return nil
	}
	// ignoring error, counter() always return nil
	_ = parser.Visit(a, "", compiled.Unset, counter, tVariable)

	// no variables in nested struct, we use fmt std print function
	if count == 0 {
		sbb.WriteString(fmt.Sprint(a))
		return
	}

	sbb.WriteByte('{')
	printer := func(visibility compiled.Visibility, name string, tValue reflect.Value) error {
		count--
		sbb.WriteString(name)
		sbb.WriteString(": ")
		sbb.WriteString("%s")
		if count != 0 {
			sbb.WriteString(", ")
		}

		v := tValue.Interface().(compiled.Variable)
		// we set limits to the linear expression, so that the log printer
		// can evaluate it before printing it
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		log.ToResolve = append(log.ToResolve, v.LinExp...)
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		return nil
	}
	// ignoring error, printer() doesn't return errors
	_ = parser.Visit(a, "", compiled.Unset, printer, tVariable)
	sbb.WriteByte('}')
}

// Tag creates a tag at a given place in a circuit. The state of the tag may contain informations needed to
// measure constraints, variables and coefficients creations through AddCounter
func (system *SparseR1CS) Tag(name string) cs.Tag {
	_, file, line, _ := runtime.Caller(1)

	return cs.Tag{
		Name: fmt.Sprintf("%s[%s:%d]", name, filepath.Base(file), line),
		VID:  system.NbInternalVariables,
		CID:  len(system.Constraints),
	}
}

// AddCounter measures the number of constraints, variables and coefficients created between two tags
// note that the PlonK statistics are contextual since there is a post-compile phase where linear expressions
// are factorized. That is, measuring 2 times the "repeating" piece of circuit may give less constraints the second time
func (system *SparseR1CS) AddCounter(from, to cs.Tag) {
	system.Counters = append(system.Counters, compiled.Counter{
		From:          from.Name,
		To:            to.Name,
		NbVariables:   to.VID - from.VID,
		NbConstraints: to.CID - from.CID,
		CurveID:       system.CurveID,
		BackendID:     backend.PLONK,
	})
}

func (system *SparseR1CS) NewHint(f hint.Function, inputs ...cs.Variable) cs.Variable {
	// create resulting wire
	r := system.newInternalVariable()
	_, vID, _ := r.Unpack()

	// mark hint as unconstrained, for now
	//system.mHintsConstrained[vID] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	//hintInputs := make([]compiled.LinearExpression, len(inputs))
	hintInputs := make([]interface{}, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case compiled.Term:
			hintInputs[i] = t
		default:
			hintInputs[i] = utils.FromInterface(in)
		}
	}

	// add the hint to the constraint system
	system.MHints[vID] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

// IsConstant returns true if v is a constant known at compile time
func (system *SparseR1CS) IsConstant(v cs.Variable) bool {
	switch t := v.(type) {
	case compiled.Term:
		return false
	default:
		utils.FromInterface(t)
		return true
	}
}

// ConstantValue returns the big.Int value of v. It
// panics if v.IsConstant() == false
func (system *SparseR1CS) ConstantValue(v cs.Variable) *big.Int {
	if !system.IsConstant(v) {
		panic("v should be a constant")
	}
	res := utils.FromInterface(v)
	return &res
}

func (system *SparseR1CS) Backend() backend.ID {
	return backend.PLONK
}

// returns in split into a slice of compiledTerm and the sum of all constants in in as a bigInt
func (system *SparseR1CS) filterConstantSum(in []cs.Variable) ([]compiled.Term, big.Int) {
	res := make([]compiled.Term, 0, len(in))
	var b big.Int
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Add(&b, &n)
		}
	}
	return res, b
}

// returns in split into a slice of compiledTerm and the product of all constants in in as a bigInt
func (system *SparseR1CS) filterConstantProd(in []cs.Variable) ([]compiled.Term, big.Int) {
	res := make([]compiled.Term, 0, len(in))
	var b big.Int
	b.SetInt64(1)
	for i := 0; i < len(in); i++ {
		switch t := in[i].(type) {
		case compiled.Term:
			res = append(res, t)
		default:
			n := utils.FromInterface(t)
			b.Mul(&b, &n)
		}
	}
	return res, b
}

func (system *SparseR1CS) splitSum(acc compiled.Term, r []compiled.Term) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := system.newInternalVariable()
	system.addPlonkConstraint(acc, r[0], o, cl, cr, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return system.splitSum(o, r[1:])
}

func (system *SparseR1CS) splitProd(acc compiled.Term, r []compiled.Term) compiled.Term {

	// floor case
	if len(r) == 0 {
		return acc
	}

	cl, _, _ := acc.Unpack()
	cr, _, _ := r[0].Unpack()
	o := system.newInternalVariable()
	system.addPlonkConstraint(acc, r[0], o, compiled.CoeffIdZero, compiled.CoeffIdZero, cl, cr, compiled.CoeffIdMinusOne, compiled.CoeffIdZero)
	return system.splitProd(o, r[1:])
}
