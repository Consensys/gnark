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
	"strings"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/std/math/bits"
)

// ---------------------------------------------------------------------------------------------
// Arithmetic

// Add returns res = i1+i2+...in
func (system *r1cs) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {

	// extract frontend.Variables from input
	vars, s := system.toVariables(append([]frontend.Variable{i1, i2}, in...)...)

	// allocate resulting frontend.Variable
	res := make(compiled.LinearExpression, 0, s)

	for _, v := range vars {
		l := v.Clone()
		res = append(res, l...)
	}

	res = system.reduce(res)

	return res
}

// Neg returns -i
func (system *r1cs) Neg(i frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(i)

	if n, ok := system.ConstantValue(vars[0]); ok {
		n.Neg(n)
		return system.toVariable(n)
	}

	return system.negateLinExp(vars[0])
}

// Sub returns res = i1 - i2
func (system *r1cs) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {

	// extract frontend.Variables from input
	vars, s := system.toVariables(append([]frontend.Variable{i1, i2}, in...)...)

	// allocate resulting frontend.Variable
	res := make(compiled.LinearExpression, 0, s)

	c := vars[0].Clone()
	res = append(res, c...)
	for i := 1; i < len(vars); i++ {
		negLinExp := system.negateLinExp(vars[i])
		res = append(res, negLinExp...)
	}

	// reduce linear expression
	res = system.reduce(res)

	return res
}

// Mul returns res = i1 * i2 * ... in
func (system *r1cs) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(append([]frontend.Variable{i1, i2}, in...)...)

	mul := func(v1, v2 compiled.LinearExpression) compiled.LinearExpression {

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
			return system.toVariable(n1).(compiled.LinearExpression)
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

func (system *r1cs) mulConstant(v1, constant compiled.LinearExpression) compiled.LinearExpression {
	// multiplying a frontend.Variable by a constant -> we updated the coefficients in the linear expression
	// leading to that frontend.Variable
	res := v1.Clone()
	lambda, _ := system.ConstantValue(constant)

	for i, t := range v1 {
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
		res[i] = compiled.Pack(vID, system.st.CoeffID(&newCoeff), visibility)
	}
	return res
}

func (system *r1cs) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(i1, i2)

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
		return system.toVariable(n2)
	}

	// v1 is not constant
	return system.mulConstant(v1, system.toVariable(n2).(compiled.LinearExpression))
}

// Div returns res = i1 / i2
func (system *r1cs) Div(i1, i2 frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(i1, i2)

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
		return system.toVariable(n2)
	}

	// v1 is not constant
	return system.mulConstant(v1, system.toVariable(n2).(compiled.LinearExpression))
}

// Inverse returns res = inverse(v)
func (system *r1cs) Inverse(i1 frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(i1)

	if c, ok := system.ConstantValue(vars[0]); ok {
		if c.IsUint64() && c.Uint64() == 0 {
			panic("inverse by constant(0)")
		}

		c.ModInverse(c, system.CurveID.Info().Fr.Modulus())
		return system.toVariable(c)
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
func (system *r1cs) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	// nbBits
	nbBits := system.BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	return bits.ToBinary(system, i1, bits.WithNbDigits(nbBits))
}

// FromBinary packs b, seen as a fr.Element in little endian
func (system *r1cs) FromBinary(_b ...frontend.Variable) frontend.Variable {
	return bits.FromBinary(system, _b)
}

// Xor compute the XOR between two frontend.Variables
func (system *r1cs) Xor(_a, _b frontend.Variable) frontend.Variable {

	vars, _ := system.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	// the formulation used is for easing up the conversion to sparse r1cs
	res := system.newInternalVariable()
	system.MarkBoolean(res)
	c := system.Neg(res).(compiled.LinearExpression)
	c = append(c, a[0], b[0])
	aa := system.Mul(a, 2)
	system.Constraints = append(system.Constraints, newR1C(aa, b, c))

	return res
}

// Or compute the OR between two frontend.Variables
func (system *r1cs) Or(_a, _b frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(_a, _b)

	a := vars[0]
	b := vars[1]

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	// the formulation used is for easing up the conversion to sparse r1cs
	res := system.newInternalVariable()
	system.MarkBoolean(res)
	c := system.Neg(res).(compiled.LinearExpression)
	c = append(c, a[0], b[0])
	system.Constraints = append(system.Constraints, newR1C(a, b, c))

	return res
}

// And compute the AND between two frontend.Variables
func (system *r1cs) And(_a, _b frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(_a, _b)

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
func (system *r1cs) Select(i0, i1, i2 frontend.Variable) frontend.Variable {

	vars, _ := system.toVariables(i0, i1, i2)
	cond := vars[0]

	// ensures that cond is boolean
	system.AssertIsBoolean(cond)

	if c, ok := system.ConstantValue(cond); ok {
		// condition is a constant return i1 if true, i2 if false
		if c.Uint64() == 1 {
			return vars[1]
		}
		return vars[2]
	}

	n1, ok1 := system.ConstantValue(vars[1])
	n2, ok2 := system.ConstantValue(vars[2])

	if ok1 && ok2 {
		diff := n1.Sub(n1, n2)
		res := system.Mul(cond, diff)  // no constraint is recorded
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
	w := system.Mul(cond, v)
	return system.Add(w, vars[2])

}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (system *r1cs) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(b0, b1, i0, i1, i2, i3)
	s0, s1 := vars[0], vars[1]
	in0, in1, in2, in3 := vars[2], vars[3], vars[4], vars[5]

	// ensure that bits are actually bits. Adds no constraints if the variables
	// are already constrained.
	system.AssertIsBoolean(s0)
	system.AssertIsBoolean(s1)

	c0, b0IsConstant := system.ConstantValue(s0)
	c1, b1IsConstant := system.ConstantValue(s1)

	if b0IsConstant && b1IsConstant {
		b0 := c0.Uint64() == 1
		b1 := c1.Uint64() == 1

		if !b0 && !b1 {
			return in0
		}
		if b0 && !b1 {
			return in1
		}
		if b0 && b1 {
			return in3
		}
		return in2
	}

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
func (system *r1cs) IsZero(i1 frontend.Variable) frontend.Variable {
	vars, _ := system.toVariables(i1)
	a := vars[0]
	if c, ok := system.ConstantValue(a); ok {
		if c.IsUint64() && c.Uint64() == 0 {
			return system.toVariable(1)
		}
		return system.toVariable(0)
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
	system.addConstraint(newR1C(a, m, system.toVariable(0)), debug)

	system.AssertIsBoolean(m)
	ma := system.Add(m, a)
	_ = system.Inverse(ma)
	return m
}

// Cmp returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2
func (system *r1cs) Cmp(i1, i2 frontend.Variable) frontend.Variable {

	vars, _ := system.toVariables(i1, i2)
	bi1 := system.ToBinary(vars[0], system.BitLen())
	bi2 := system.ToBinary(vars[1], system.BitLen())

	res := system.toVariable(0)

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

// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a variable, its value will be resolved avec R1CS.Solve() method is called
func (system *r1cs) Println(a ...frontend.Variable) {
	var log compiled.LogEntry

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		log.Caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	var sbb strings.Builder

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		if v, ok := arg.(compiled.LinearExpression); ok {
			assertIsSet(v)

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
			log.ToResolve = append(log.ToResolve, v...)
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		} else {
			printArg(&log, &sbb, arg)
		}
	}

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

		v := tValue.Interface().(compiled.LinearExpression)
		// we set limits to the linear expression, so that the log printer
		// can evaluate it before printing it
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		log.ToResolve = append(log.ToResolve, v...)
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		return nil
	}
	// ignoring error, printer() doesn't return errors
	_, _ = schema.Parse(a, tVariable, printer)
	sbb.WriteByte('}')
}

// returns -le, the result is a copy
func (system *r1cs) negateLinExp(l compiled.LinearExpression) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(l))
	var lambda big.Int
	for i, t := range l {
		cID, vID, visibility := t.Unpack()
		lambda.Neg(&system.st.Coeffs[cID])
		cID = system.st.CoeffID(&lambda)
		res[i] = compiled.Pack(vID, cID, visibility)
	}
	return res
}

func (system *r1cs) Compiler() frontend.Compiler {
	return system
}
