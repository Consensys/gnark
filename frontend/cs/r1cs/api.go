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

package r1cs

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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/utils"
)

// ---------------------------------------------------------------------------------------------
// Arithmetic

// Add returns res = i1+i2+...in
func (system *r1CS) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {

	// extract frontend.Variables from input
	vars, s := system.ToSymbols(append([]frontend.Variable{i1, i2}, in...)...)

	// allocate resulting frontend.Variable
	res := compiled.Variable{LinExp: make([]compiled.Term, 0, s)}

	for _, v := range vars {
		l := v.Clone()
		res.LinExp = append(res.LinExp, l.LinExp...)
	}

	res = system.reduce(res)

	return res
}

// Neg returns -i
func (system *r1CS) Neg(i frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(i)

	if n, ok := system.ConstantValue(vars[0]); ok {
		n.Neg(n)
		return system.ToVariable(n)
	}

	res := compiled.Variable{LinExp: system.negateLinExp(vars[0].LinExp)}

	return res
}

// Sub returns res = i1 - i2
func (system *r1CS) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {

	// extract frontend.Variables from input
	vars, s := system.ToSymbols(append([]frontend.Variable{i1, i2}, in...)...)

	// allocate resulting frontend.Variable
	res := compiled.Variable{
		LinExp: make([]compiled.Term, 0, s),
	}

	c := vars[0].Clone()
	res.LinExp = append(res.LinExp, c.LinExp...)
	for i := 1; i < len(vars); i++ {
		negLinExp := system.negateLinExp(vars[i].LinExp)
		res.LinExp = append(res.LinExp, negLinExp...)
	}

	// reduce linear expression
	res = system.reduce(res)

	return res
}

// Mul returns res = i1 * i2 * ... in
func (system *r1CS) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(append([]frontend.Variable{i1, i2}, in...)...)

	mul := func(v1, v2 compiled.Variable) compiled.Variable {

		n1, v1Constant := system.ConstantValue(v1)
		n2, v2Constant := system.ConstantValue(v2)

		// v1 and v2 are both unknown, this is the only case we add a constraint
		if !v1Constant && !v2Constant {
			res := system.newInternalVariable()
			system.Constraints = append(system.Constraints, newR1C(v1, v2, res))
			return res
		}

		// v1 and v2 are constants, we multiply big.Int values and return resulting constant
		if v1Constant && v2Constant {
			n1.Mul(n1, n2).Mod(n1, system.CurveID.Info().Fr.Modulus())
			return system.ToVariable(n1).(compiled.Variable)
		}

		// ensure v2 is the constant
		if v1Constant {
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

func (system *r1CS) mulConstant(v1, constant compiled.Variable) compiled.Variable {
	// multiplying a frontend.Variable by a constant -> we updated the coefficients in the linear expression
	// leading to that frontend.Variable
	res := v1.Clone()
	lambda, _ := system.ConstantValue(constant)

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
			coeff := system.st.Coeffs[cID]
			newCoeff.Mul(&coeff, lambda)
		}
		res.LinExp[i] = compiled.Pack(vID, system.st.CoeffID(&newCoeff), visibility)
	}
	return res
}

func (system *r1CS) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	n1, v1Constant := system.ConstantValue(v1)
	n2, v2Constant := system.ConstantValue(v2)

	if !v2Constant {
		res := system.newInternalVariable()
		debug := system.AddDebugInfo("div", v1, "/", v2, " == ", res)
		// note that here we don't ensure that divisor is != 0
		system.addConstraint(newR1C(v2, res, v1), debug)
		return res
	}

	// v2 is constant
	if n2.IsUint64() && n2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := system.CurveID.Info().Fr.Modulus()
	n2.ModInverse(n2, q)

	if v1Constant {
		n2.Mul(n2, n1).Mod(n2, q)
		return system.ToVariable(n2)
	}

	// v1 is not constant
	return system.mulConstant(v1, system.ToVariable(n2).(compiled.Variable))
}

// Div returns res = i1 / i2
func (system *r1CS) Div(i1, i2 frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(i1, i2)

	v1 := vars[0]
	v2 := vars[1]

	n1, v1Constant := system.ConstantValue(v1)
	n2, v2Constant := system.ConstantValue(v2)

	if !v2Constant {
		res := system.newInternalVariable()
		debug := system.AddDebugInfo("div", v1, "/", v2, " == ", res)
		v2Inv := system.newInternalVariable()
		// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
		system.addConstraint(newR1C(v2, v2Inv, system.one()), debug)
		system.addConstraint(newR1C(v1, v2Inv, res), debug)
		return res
	}

	// v2 is constant
	if n2.IsUint64() && n2.Uint64() == 0 {
		panic("div by constant(0)")
	}
	q := system.CurveID.Info().Fr.Modulus()
	n2.ModInverse(n2, q)

	if v1Constant {
		n2.Mul(n2, n1).Mod(n2, q)
		return system.ToVariable(n2)
	}

	// v1 is not constant
	return system.mulConstant(v1, system.ToVariable(n2).(compiled.Variable))
}

// Inverse returns res = inverse(v)
func (system *r1CS) Inverse(i1 frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(i1)

	if c, ok := system.ConstantValue(vars[0]); ok {
		if c.IsUint64() && c.Uint64() == 0 {
			panic("inverse by constant(0)")
		}

		c.ModInverse(c, system.CurveID.Info().Fr.Modulus())
		return system.ToVariable(c)
	}

	// allocate resulting frontend.Variable
	res := system.newInternalVariable()

	debug := system.AddDebugInfo("inverse", vars[0], "*", res, " == 1")
	system.addConstraint(newR1C(res, vars[0], system.one()), debug)

	return res
}

// ---------------------------------------------------------------------------------------------
// Bit operations

// ToBinary unpacks a frontend.Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (system *r1CS) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {

	// nbBits
	nbBits := system.BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	vars, _ := system.ToSymbols(i1)
	a := vars[0]

	// if a is a constant, work with the big int value.
	if c, ok := system.ConstantValue(a); ok {
		b := make([]frontend.Variable, nbBits)
		for i := 0; i < len(b); i++ {
			b[i] = system.ToVariable(c.Bit(i))
		}
		return b
	}

	return system.toBinary(a, nbBits, false)
}

// toBinary is equivalent to ToBinary, exept the returned bits are NOT boolean constrained.
func (system *r1CS) toBinary(a compiled.Variable, nbBits int, unsafe bool) []frontend.Variable {

	if _, ok := system.ConstantValue(a); ok {
		return system.ToBinary(a, nbBits)
	}

	// ensure a is set
	a.AssertIsSet()

	// allocate the resulting frontend.Variables and bit-constraint them
	sb := make([]frontend.Variable, nbBits)
	var c big.Int
	c.SetUint64(1)

	bits, err := system.NewHint(hint.NBits, nbBits, a)
	if err != nil {
		panic(err)
	}

	for i := 0; i < nbBits; i++ {
		sb[i] = system.Mul(bits[i], c)
		c.Lsh(&c, 1)
		if !unsafe {
			system.AssertIsBoolean(bits[i])
		}
	}

	//var Σbi compiled.Variable
	var Σbi frontend.Variable
	if nbBits == 1 {
		system.AssertIsEqual(sb[0], a)
	} else if nbBits == 2 {
		Σbi = system.Add(sb[0], sb[1])
	} else {
		Σbi = system.Add(sb[0], sb[1], sb[2:]...)
	}
	system.AssertIsEqual(Σbi, a)

	// record the constraint Σ (2**i * b[i]) == a
	return bits

}

// FromBinary packs b, seen as a fr.Element in little endian
func (system *r1CS) FromBinary(_b ...frontend.Variable) frontend.Variable {
	b, _ := system.ToSymbols(_b...)

	// ensure inputs are set
	for i := 0; i < len(b); i++ {
		b[i].AssertIsSet()
	}

	// res = Σ (2**i * b[i])

	var res, v frontend.Variable
	res = system.ToVariable(0) // no constraint is recorded

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

// Xor compute the XOR between two frontend.Variables
func (system *r1CS) Xor(_a, _b frontend.Variable) frontend.Variable {

	vars, _ := system.ToSymbols(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	// the formulation used is for easing up the conversion to sparse r1cs
	res := system.newInternalVariable()
	system.MarkBoolean(res)
	c := system.Neg(res).(compiled.Variable)
	c.LinExp = append(c.LinExp, a.LinExp[0], b.LinExp[0])
	aa := system.Mul(a, 2)
	system.Constraints = append(system.Constraints, newR1C(aa, b, c))

	return res
}

// Or compute the OR between two frontend.Variables
func (system *r1CS) Or(_a, _b frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	// the formulation used is for easing up the conversion to sparse r1cs
	res := system.newInternalVariable()
	system.MarkBoolean(res)
	c := system.Neg(res).(compiled.Variable)
	c.LinExp = append(c.LinExp, a.LinExp[0], b.LinExp[0])
	system.Constraints = append(system.Constraints, newR1C(a, b, c))

	return res
}

// And compute the AND between two frontend.Variables
func (system *r1CS) And(_a, _b frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	res := system.Mul(a, b)

	return res
}

// ---------------------------------------------------------------------------------------------
// Conditionals

// Select if i0 is true, yields i1 else yields i2
func (system *r1CS) Select(i0, i1, i2 frontend.Variable) frontend.Variable {

	vars, _ := system.ToSymbols(i0, i1, i2)
	b := vars[0]

	// ensures that b is boolean
	system.AssertIsBoolean(b)
	n1, ok1 := system.ConstantValue(vars[1])
	n2, ok2 := system.ConstantValue(vars[2])

	if ok1 && ok2 {
		diff := n1.Sub(n1, n2)
		res := system.Mul(b, diff)     // no constraint is recorded
		res = system.Add(res, vars[2]) // no constraint is recorded
		return res
	}

	// special case appearing in AssertIsLessOrEq
	if ok1 {
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
func (system *r1CS) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(b0, b1, i0, i1, i2, i3)
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

// IsZero returns 1 if i1 is zero, 0 otherwise
func (system *r1CS) IsZero(i1 frontend.Variable) frontend.Variable {
	vars, _ := system.ToSymbols(i1)
	a := vars[0]
	if c, ok := system.ConstantValue(a); ok {
		if c.IsUint64() && c.Uint64() == 0 {
			return system.ToVariable(1)
		}
		return system.ToVariable(0)
	}

	debug := system.AddDebugInfo("isZero", a)

	//m * (1 - m) = 0       // constrain m to be 0 or 1
	// a * m = 0            // constrain m to be 0 if a != 0
	// _ = inverse(m + a) 	// constrain m to be 1 if a == 0

	// m is computed by the solver such that m = 1 - a^(modulus - 1)
	res, err := system.NewHint(hint.IsZero, 1, a)
	if err != nil {
		// the function errs only if the number of inputs is invalid.
		panic(err)
	}
	m := res[0]
	system.addConstraint(newR1C(a, m, system.ToVariable(0)), debug)

	system.AssertIsBoolean(m)
	ma := system.Add(m, a)
	_ = system.Inverse(ma)
	return m
}

// Cmp returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2
func (system *r1CS) Cmp(i1, i2 frontend.Variable) frontend.Variable {

	vars, _ := system.ToSymbols(i1, i2)
	bi1 := system.ToBinary(vars[0], system.BitLen())
	bi2 := system.ToBinary(vars[1], system.BitLen())

	res := system.ToVariable(0)

	for i := system.BitLen() - 1; i >= 0; i-- {

		iszeroi1 := system.IsZero(bi1[i])
		iszeroi2 := system.IsZero(bi2[i])

		i1i2 := system.And(bi1[i], iszeroi2)
		i2i1 := system.And(bi2[i], iszeroi1)

		n := system.Select(i2i1, -1, 0)
		m := system.Select(i1i2, 1, n)

		res = system.Select(system.IsZero(res), m, res)

	}
	return res
}

// ---------------------------------------------------------------------------------------------
// Assertions

// ConstantValue returns the big.Int value of v.
// Will panic if v.IsConstant() == false
func (system *r1CS) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	if _v, ok := v.(compiled.Variable); ok {
		_v.AssertIsSet()

		if len(_v.LinExp) != 1 {
			return nil, false
		}
		cID, vID, visibility := _v.LinExp[0].Unpack()
		if !(vID == 0 && visibility == schema.Public) {
			return nil, false
		}
		return new(big.Int).Set(&system.st.Coeffs[cID]), true
	}
	r := utils.FromInterface(v)
	return &r, true
}

func (system *r1CS) Backend() backend.ID {
	return backend.GROTH16
}

// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a variable, its value will be resolved avec R1CS.Solve() method is called
func (system *r1CS) Println(a ...frontend.Variable) {
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

	system.Logs = append(system.Logs, log)
}

func printArg(log *compiled.LogEntry, sbb *strings.Builder, a frontend.Variable) {

	count := 0
	counter := func(visibility schema.Visibility, name string, tValue reflect.Value) error {
		count++
		return nil
	}
	// ignoring error, counter() always return nil
	_, _ = schema.Parse(a, tVariable, counter)

	// no variables in nested struct, we use fmt std print function
	if count == 0 {
		sbb.WriteString(fmt.Sprint(a))
		return
	}

	sbb.WriteByte('{')
	printer := func(visibility schema.Visibility, name string, tValue reflect.Value) error {
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
	_, _ = schema.Parse(a, tVariable, printer)
	sbb.WriteByte('}')
}

// Tag creates a tag at a given place in a circuit. The state of the tag may contain informations needed to
// measure constraints, variables and coefficients creations through AddCounter
func (system *r1CS) Tag(name string) frontend.Tag {
	_, file, line, _ := runtime.Caller(1)

	return frontend.Tag{
		Name: fmt.Sprintf("%s[%s:%d]", name, filepath.Base(file), line),
		VID:  system.NbInternalVariables,
		CID:  len(system.Constraints),
	}
}

// AddCounter measures the number of constraints, variables and coefficients created between two tags
func (system *r1CS) AddCounter(from, to frontend.Tag) {
	system.Counters = append(system.Counters, compiled.Counter{
		From:          from.Name,
		To:            to.Name,
		NbVariables:   to.VID - from.VID,
		NbConstraints: to.CID - from.CID,
		CurveID:       system.CurveID,
		BackendID:     backend.GROTH16,
	})
}

// NewHint initializes internal variables whose value will be evaluated using
// the provided hint function at run time from the inputs. Inputs must be either
// variables or convertible to *big.Int. The function returns an error if the
// number of inputs is not compatible with f.
//
// The hint function is provided at the proof creation time and is not embedded
// into the circuit. From the backend point of view, the variable returned by
// the hint function is equivalent to the user-supplied witness, but its actual
// value is assigned by the solver, not the caller.
//
// No new constraints are added to the newly created wire and must be added
// manually in the circuit. Failing to do so leads to solver failure.
func (system *r1CS) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {

	if nbOutputs <= 0 {
		return nil, fmt.Errorf("hint function must return at least one output")
	}
	hintInputs := make([]interface{}, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case compiled.Variable:
			tmp := t.Clone()
			hintInputs[i] = tmp.LinExp
		case compiled.LinearExpression:
			tmp := make(compiled.LinearExpression, len(t))
			copy(tmp, t)
			hintInputs[i] = tmp
		default:
			hintInputs[i] = utils.FromInterface(t)
		}
	}

	// prepare wires
	varIDs := make([]int, nbOutputs)
	res := make([]frontend.Variable, len(varIDs))
	for i := range varIDs {
		r := system.newInternalVariable()
		_, vID, _ := r.LinExp[0].Unpack()
		varIDs[i] = vID
		res[i] = r
	}

	ch := &compiled.Hint{ID: f.UUID(), Inputs: hintInputs, Wires: varIDs}
	for _, vID := range varIDs {
		system.MHints[vID] = ch
	}

	return res, nil
}

// ToVariable will return (and allocate if neccesary) a frontend.Variable from given value
//
// if input is already a frontend.Variable, does nothing
// else, attempts to convert input to a big.Int (see utils.FromInterface) and returns a ToVariable frontend.Variable
//
// a ToVariable frontend.Variable does NOT necessary allocate a frontend.Variable in the ConstraintSystem
// it is in the form ONE_WIRE * coeff
func (system *r1CS) ToVariable(input interface{}) frontend.Variable {

	switch t := input.(type) {
	case compiled.Variable:
		t.AssertIsSet()
		return t
	default:
		n := utils.FromInterface(t)
		if n.IsUint64() && n.Uint64() == 1 {
			return system.one()
		}
		r := system.one()
		r.LinExp[0] = system.setCoeff(r.LinExp[0], &n)
		return r
	}
}

// ToSymbols return frontend.Variable corresponding to inputs and the total size of the linear expressions
func (system *r1CS) ToSymbols(in ...frontend.Variable) ([]compiled.Variable, int) {
	r := make([]compiled.Variable, 0, len(in))
	s := 0
	e := func(i frontend.Variable) {
		v := system.ToVariable(i).(compiled.Variable)
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
func (system *r1CS) negateLinExp(l []compiled.Term) []compiled.Term {
	res := make([]compiled.Term, len(l))
	var lambda big.Int
	for i, t := range l {
		cID, vID, visibility := t.Unpack()
		lambda.Neg(&system.st.Coeffs[cID])
		cID = system.st.CoeffID(&lambda)
		res[i] = compiled.Pack(vID, cID, visibility)
	}
	return res
}

func (system *r1CS) Compiler() frontend.Compiler {
	return system
}
