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

package scs

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
	"github.com/consensys/gnark/frontend/field"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/std/math/bits"
)

// Add returns res = i1+i2+...in
func (system *scs[E, ptE]) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	zero := big.NewInt(0)
	vars, k := system.filterConstantSum(append([]frontend.Variable{i1, i2}, in...))

	if len(vars) == 0 {
		return k
	}
	vars = system.reduce(vars)
	if k.Cmp(zero) == 0 {
		return system.splitSum(vars[0], vars[1:])
	}
	cl, _, _ := vars[0].Unpack()
	var kFr E
	ptE(&kFr).SetBigInt(&k)
	o := system.newInternalVariable()
	system.addPlonkConstraint(vars[0], system.zero(), o, cl, field.Zero[E, ptE](), field.Zero[E, ptE](), field.Zero[E, ptE](), field.NegOne[E, ptE](), kFr)
	return system.splitSum(o, vars[1:])

}

// neg returns -in
func (system *scs[E, ptE]) neg(in []frontend.Variable) []frontend.Variable {

	res := make([]frontend.Variable, len(in))

	for i := 0; i < len(in); i++ {
		res[i] = system.Neg(in[i])
	}
	return res
}

// Sub returns res = i1 - i2 - ...in
func (system *scs[E, ptE]) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	r := system.neg(append([]frontend.Variable{i2}, in...))
	return system.Add(i1, r[0], r[1:]...)
}

// Neg returns -i
func (system *scs[E, ptE]) Neg(i1 frontend.Variable) frontend.Variable {
	if n, ok := system.ConstantValue(i1); ok {
		n.Neg(n)
		return *n
	} else {
		v := i1.(compiled.Term[E, ptE])
		c, _, _ := v.Unpack()
		var negCoeff E
		ptE(&negCoeff).Neg(&c)
		v.SetCoeff(negCoeff)
		return v
	}
}

// Mul returns res = i1 * i2 * ... in
func (system *scs[E, ptE]) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {

	vars, k := system.filterConstantProd(append([]frontend.Variable{i1, i2}, in...))
	if len(vars) == 0 {
		return k
	}
	l := system.mulConstant(vars[0], &k)
	return system.splitProd(l, vars[1:])

}

// returns t*m
func (system *scs[E, ptE]) mulConstant(t compiled.Term[E, ptE], m *big.Int) compiled.Term[E, ptE] {
	cid, _, _ := t.Unpack()
	var mFr E
	ptE(&mFr).SetBigInt(m)
	ptE(&mFr).Mul(&cid, &mFr)
	t.SetCoeff(mFr)
	return t
}

// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
func (system *scs[E, ptE]) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	c1, i1Constant := system.ConstantValue(i1)
	c2, i2Constant := system.ConstantValue(i2)

	if i1Constant && i2Constant {
		l := c1
		r := c2
		q := system.q
		return r.ModInverse(r, q).
			Mul(l, r).
			Mod(r, q)
	}
	if i2Constant {
		c := c2
		q := system.q
		c.ModInverse(c, q)
		return system.mulConstant(i1.(compiled.Term[E, ptE]), c)
	}
	if i1Constant {
		res := system.Inverse(i2)
		return system.mulConstant(res.(compiled.Term[E, ptE]), c1)
	}

	res := system.newInternalVariable()
	r := i2.(compiled.Term[E, ptE])
	o := system.Neg(i1).(compiled.Term[E, ptE])
	cr, _, _ := r.Unpack()
	co, _, _ := o.Unpack()
	system.addPlonkConstraint(res, r, o, field.Zero[E, ptE](), field.Zero[E, ptE](), field.One[E, ptE](), cr, co, field.Zero[E, ptE]())
	return res
}

// Div returns i1 / i2
func (system *scs[E, ptE]) Div(i1, i2 frontend.Variable) frontend.Variable {

	// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
	system.Inverse(i2)

	return system.DivUnchecked(i1, i2)
}

// Inverse returns res = 1 / i1
func (system *scs[E, ptE]) Inverse(i1 frontend.Variable) frontend.Variable {
	if c, ok := system.ConstantValue(i1); ok {
		c.ModInverse(c, system.q)
		return c
	}
	t := i1.(compiled.Term[E, ptE])
	cr, _, _ := t.Unpack()
	debug := system.AddDebugInfo("inverse", "1/", i1, " < ∞")
	res := system.newInternalVariable()
	system.addPlonkConstraint(res, t, system.zero(), field.Zero[E, ptE](), field.Zero[E, ptE](), field.One[E, ptE](), cr, field.Zero[E, ptE](), field.NegOne[E, ptE](), debug)
	return res
}

// ---------------------------------------------------------------------------------------------
// Bit operations

// ToBinary unpacks a frontend.Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result in in little endian (first bit= lsb)
func (system *scs[E, ptE]) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	// nbBits
	nbBits := system.FieldBitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	return bits.ToBinary(system, i1, bits.WithNbDigits(nbBits))
}

// FromBinary packs b, seen as a fr.Element in little endian
func (system *scs[E, ptE]) FromBinary(b ...frontend.Variable) frontend.Variable {
	return bits.FromBinary(system, b)
}

// Xor returns a ^ b
// a and b must be 0 or 1
func (system *scs[E, ptE]) Xor(a, b frontend.Variable) frontend.Variable {

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)
	_a, aConstant := system.ConstantValue(a)
	_b, bConstant := system.ConstantValue(b)

	if aConstant && bConstant {
		_a.Xor(_a, _b)
		return _a
	}

	res := system.newInternalVariable()
	system.MarkBoolean(res)
	if aConstant {
		a, b = b, a
		bConstant = aConstant
		_b = _a
	}
	if bConstant {
		l := a.(compiled.Term[E, ptE])
		r := l
		var oneMinusTwoB, bFr E
		ptE(&bFr).SetBigInt(_b)
		ptE(&oneMinusTwoB).SetInt64(1)
		ptE(&oneMinusTwoB).Sub(&oneMinusTwoB, &bFr)
		ptE(&oneMinusTwoB).Sub(&oneMinusTwoB, &bFr)
		system.addPlonkConstraint(l, r, res, oneMinusTwoB, field.Zero[E, ptE](), field.Zero[E, ptE](), field.Zero[E, ptE](), field.NegOne[E, ptE](), bFr)
		return res
	}
	l := a.(compiled.Term[E, ptE])
	r := b.(compiled.Term[E, ptE])
	var two E
	ptE(&two).SetInt64(2)
	system.addPlonkConstraint(l, r, res, field.NegOne[E, ptE](), field.NegOne[E, ptE](), two, field.One[E, ptE](), field.One[E, ptE](), field.Zero[E, ptE]())
	return res
}

// Or returns a | b
// a and b must be 0 or 1
func (system *scs[E, ptE]) Or(a, b frontend.Variable) frontend.Variable {

	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)

	_a, aConstant := system.ConstantValue(a)
	_b, bConstant := system.ConstantValue(b)

	if aConstant && bConstant {
		_a.Or(_a, _b)
		return _a
	}
	res := system.newInternalVariable()
	system.MarkBoolean(res)
	if aConstant {
		a, b = b, a
		_b = _a
		bConstant = aConstant
	}
	if bConstant {
		l := a.(compiled.Term[E, ptE])
		r := l

		one := field.One[E, ptE]()
		var idlFr E
		ptE(&idlFr).SetBigInt(_b)
		ptE(&idlFr).Sub(&idlFr, &one)
		system.addPlonkConstraint(l, r, res, idlFr, field.Zero[E, ptE](), field.Zero[E, ptE](), field.Zero[E, ptE](), field.One[E, ptE](), field.Zero[E, ptE]())
		return res
	}
	l := a.(compiled.Term[E, ptE])
	r := b.(compiled.Term[E, ptE])
	system.addPlonkConstraint(l, r, res, field.NegOne[E, ptE](), field.NegOne[E, ptE](), field.One[E, ptE](), field.One[E, ptE](), field.One[E, ptE](), field.Zero[E, ptE]())
	return res
}

// Or returns a & b
// a and b must be 0 or 1
func (system *scs[E, ptE]) And(a, b frontend.Variable) frontend.Variable {
	system.AssertIsBoolean(a)
	system.AssertIsBoolean(b)
	res := system.Mul(a, b)
	system.MarkBoolean(res)
	return res
}

// ---------------------------------------------------------------------------------------------
// Conditionals

// Select if b is true, yields i1 else yields i2
func (system *scs[E, ptE]) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	_b, bConstant := system.ConstantValue(b)

	if bConstant {
		if !(_b.IsUint64() && (_b.Uint64() <= 1)) {
			panic(fmt.Sprintf("%s should be 0 or 1", _b.String()))
		}
		if _b.Uint64() == 0 {
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
func (system *scs[E, ptE]) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {

	// vars, _ := system.toVariables(b0, b1, i0, i1, i2, i3)
	// s0, s1 := vars[0], vars[1]
	// in0, in1, in2, in3 := vars[2], vars[3], vars[4], vars[5]

	// ensure that bits are actually bits. Adds no constraints if the variables
	// are already constrained.
	system.AssertIsBoolean(b0)
	system.AssertIsBoolean(b1)

	c0, b0IsConstant := system.ConstantValue(b0)
	c1, b1IsConstant := system.ConstantValue(b1)

	if b0IsConstant && b1IsConstant {
		b0 := c0.Uint64() == 1
		b1 := c1.Uint64() == 1

		if !b0 && !b1 {
			return i0
		}
		if b0 && !b1 {
			return i1
		}
		if b0 && b1 {
			return i3
		}
		return i2
	}

	// two-bit lookup for the general case can be done with three constraints as
	// following:
	//    (1) (in3 - in2 - in1 + in0) * s1 = tmp1 - in1 + in0
	//    (2) tmp1 * s0 = tmp2
	//    (3) (in2 - in0) * s1 = RES - tmp2 - in0
	// the variables tmp1 and tmp2 are new internal variables and the variables
	// RES will be the returned result

	// TODO check how it can be optimized for PLONK (currently it's a copy
	// paste of the r1cs version)
	tmp1 := system.Add(i3, i0)
	tmp1 = system.Sub(tmp1, i2, i1)
	tmp1 = system.Mul(tmp1, b1)
	tmp1 = system.Add(tmp1, i1)
	tmp1 = system.Sub(tmp1, i0)  // (1) tmp1 = s1 * (in3 - in2 - in1 + in0) + in1 - in0
	tmp2 := system.Mul(tmp1, b0) // (2) tmp2 = tmp1 * s0
	res := system.Sub(i2, i0)
	res = system.Mul(res, b1)
	res = system.Add(res, tmp2, i0) // (3) res = (v2 - v0) * s1 + tmp2 + in0

	return res

}

// IsZero returns 1 if a is zero, 0 otherwise
func (system *scs[E, ptE]) IsZero(i1 frontend.Variable) frontend.Variable {
	if a, ok := system.ConstantValue(i1); ok {
		if !(a.IsUint64() && a.Uint64() == 0) {
			return 0
		}
		return 1
	}

	// x = 1/a 				// in a hint (x == 0 if a == 0)
	// m = -a*x + 1         // constrain m to be 1 if a == 0
	// a * m = 0            // constrain m to be 0 if a != 0
	a := i1.(compiled.Term[E, ptE])
	m := system.newInternalVariable()

	// x = 1/a 				// in a hint (x == 0 if a == 0)
	x, err := system.NewHint(hint.InvZero, 1, a)
	if err != nil {
		// the function errs only if the number of inputs is invalid.
		panic(err)
	}

	// m = -a*x + 1         // constrain m to be 1 if a == 0
	// a*x + m - 1 == 0
	system.addPlonkConstraint(a,
		x[0].(compiled.Term[E, ptE]),
		m,
		field.Zero[E, ptE](),
		field.Zero[E, ptE](),
		field.One[E, ptE](),
		field.One[E, ptE](),
		field.One[E, ptE](),
		field.NegOne[E, ptE]())

	// a * m = 0            // constrain m to be 0 if a != 0
	system.addPlonkConstraint(a, m, system.zero(), field.Zero[E, ptE](), field.Zero[E, ptE](), field.One[E, ptE](), field.One[E, ptE](), field.Zero[E, ptE](), field.Zero[E, ptE]())

	return m
}

// Cmp returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2
func (system *scs[E, ptE]) Cmp(i1, i2 frontend.Variable) frontend.Variable {

	bi1 := system.ToBinary(i1, system.FieldBitLen())
	bi2 := system.ToBinary(i2, system.FieldBitLen())

	var res frontend.Variable
	res = 0

	for i := system.FieldBitLen() - 1; i >= 0; i-- {

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

// Println behaves like fmt.Println but accepts Variable as parameter
// whose value will be resolved at runtime when computed by the solver
// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a variable, its value will be resolved avec R1CS.Solve() method is called
func (system *scs[E, ptE]) Println(a ...frontend.Variable) {
	var log compiled.LogEntry[E, ptE]

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		log.Caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	var sbb strings.Builder

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		if v, ok := arg.(compiled.Term[E, ptE]); ok {

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor[E, ptE]())
			log.ToResolve = append(log.ToResolve, v)
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor[E, ptE]())
		} else {
			printArg(&log, &sbb, arg)
		}
	}

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	log.Format = sbb.String()

	system.Logs = append(system.Logs, log)
}

func printArg[E field.El, ptE field.PtEl[E]](log *compiled.LogEntry[E, ptE], sbb *strings.Builder, a frontend.Variable) {

	count := 0
	counter := func(f *schema.Field, tValue reflect.Value) error {
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
	printer := func(f *schema.Field, tValue reflect.Value) error {
		count--
		sbb.WriteString(f.FullName)
		sbb.WriteString(": ")
		sbb.WriteString("%s")
		if count != 0 {
			sbb.WriteString(", ")
		}

		v := tValue.Interface().(compiled.Term[E, ptE])
		// we set limits to the linear expression, so that the log printer
		// can evaluate it before printing it
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor[E, ptE]())
		log.ToResolve = append(log.ToResolve, v)
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor[E, ptE]())
		return nil
	}
	// ignoring error, printer() doesn't return errors
	_, _ = schema.Parse(a, tVariable, printer)
	sbb.WriteByte('}')
}

func (system *scs[E, ptE]) Compiler() frontend.Compiler {
	return system
}
