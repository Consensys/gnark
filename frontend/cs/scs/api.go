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
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/std/math/bits"
)

// Add returns res = i1+i2+...in
func (builder *scs) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	zero := big.NewInt(0)
	vars, k := builder.filterConstantSum(append([]frontend.Variable{i1, i2}, in...))

	if len(vars) == 0 {
		return k
	}
	vars = builder.reduce(vars)
	if k.Cmp(zero) == 0 {
		return builder.splitSum(vars[0], vars[1:])
	}
	cl, _ := vars[0].Unpack()
	kID := builder.st.CoeffID(&k)
	o := builder.newInternalVariable()
	builder.addPlonkConstraint(vars[0], builder.zero(), o, cl, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdMinusOne, kID)
	return builder.splitSum(o, vars[1:])

}

func (builder *scs) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	// TODO can we do better here to limit allocations?
	// technically we could do that in one PlonK constraint (against 2 for separate Add & Mul)
	return builder.Add(a, builder.Mul(b, c))
}

// neg returns -in
func (builder *scs) neg(in []frontend.Variable) []frontend.Variable {

	res := make([]frontend.Variable, len(in))

	for i := 0; i < len(in); i++ {
		res[i] = builder.Neg(in[i])
	}
	return res
}

// Sub returns res = i1 - i2 - ...in
func (builder *scs) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	r := builder.neg(append([]frontend.Variable{i2}, in...))
	return builder.Add(i1, r[0], r[1:]...)
}

// Neg returns -i
func (builder *scs) Neg(i1 frontend.Variable) frontend.Variable {
	if n, ok := builder.ConstantValue(i1); ok {
		n.Neg(n)
		return *n
	} else {
		v := i1.(expr.TermToRefactor)
		c, _ := v.Unpack()
		var coef big.Int
		coef.Set(&builder.st.Coeffs[c])
		coef.Neg(&coef)
		c = builder.st.CoeffID(&coef)
		v.SetCoeffID(c)
		return v
	}
}

// Mul returns res = i1 * i2 * ... in
func (builder *scs) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {

	vars, k := builder.filterConstantProd(append([]frontend.Variable{i1, i2}, in...))
	if len(vars) == 0 {
		return k
	}
	l := builder.mulConstant(vars[0], &k)
	return builder.splitProd(l, vars[1:])

}

// returns t*m
func (builder *scs) mulConstant(t expr.TermToRefactor, m *big.Int) expr.TermToRefactor {
	var coef big.Int
	cid, _ := t.Unpack()
	coef.Set(&builder.st.Coeffs[cid])
	coef.Mul(m, &coef).Mod(&coef, builder.q)
	cid = builder.st.CoeffID(&coef)
	t.SetCoeffID(cid)
	return t
}

// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
func (builder *scs) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	c1, i1Constant := builder.ConstantValue(i1)
	c2, i2Constant := builder.ConstantValue(i2)

	if i1Constant && i2Constant {
		l := c1
		r := c2
		q := builder.q
		return r.ModInverse(r, q).
			Mul(l, r).
			Mod(r, q)
	}
	if i2Constant {
		c := c2
		q := builder.q
		c.ModInverse(c, q)
		return builder.mulConstant(i1.(expr.TermToRefactor), c)
	}
	if i1Constant {
		res := builder.Inverse(i2)
		return builder.mulConstant(res.(expr.TermToRefactor), c1)
	}

	res := builder.newInternalVariable()
	r := i2.(expr.TermToRefactor)
	o := builder.Neg(i1).(expr.TermToRefactor)
	cr, _ := r.Unpack()
	co, _ := o.Unpack()
	builder.addPlonkConstraint(res, r, o, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdOne, cr, co, constraint.CoeffIdZero)
	return res
}

// Div returns i1 / i2
func (builder *scs) Div(i1, i2 frontend.Variable) frontend.Variable {

	// note that here we ensure that v2 can't be 0, but it costs us one extra constraint
	builder.Inverse(i2)

	return builder.DivUnchecked(i1, i2)
}

// Inverse returns res = 1 / i1
func (builder *scs) Inverse(i1 frontend.Variable) frontend.Variable {
	if c, ok := builder.ConstantValue(i1); ok {
		c.ModInverse(c, builder.q)
		return c
	}
	t := i1.(expr.TermToRefactor)
	cr, _ := t.Unpack()
	debug := builder.newDebugInfo("inverse", "1/", i1, " < ∞")
	res := builder.newInternalVariable()
	builder.addPlonkConstraint(res, t, builder.zero(), constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdOne, cr, constraint.CoeffIdZero, constraint.CoeffIdMinusOne, debug)
	return res
}

// ---------------------------------------------------------------------------------------------
// Bit operations

// ToBinary unpacks a frontend.Variable in binary,
// n is the number of bits to select (starting from lsb)
// n default value is fr.Bits the number of bits needed to represent a field element
//
// The result is in little endian (first bit= lsb)
func (builder *scs) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	// nbBits
	nbBits := builder.cs.FieldBitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	return bits.ToBinary(builder, i1, bits.WithNbDigits(nbBits))
}

// FromBinary packs b, seen as a fr.Element in little endian
func (builder *scs) FromBinary(b ...frontend.Variable) frontend.Variable {
	return bits.FromBinary(builder, b)
}

// Xor returns a ^ b
// a and b must be 0 or 1
func (builder *scs) Xor(a, b frontend.Variable) frontend.Variable {

	builder.AssertIsBoolean(a)
	builder.AssertIsBoolean(b)
	_a, aConstant := builder.ConstantValue(a)
	_b, bConstant := builder.ConstantValue(b)

	if aConstant && bConstant {
		_a.Xor(_a, _b)
		return _a
	}

	res := builder.newInternalVariable()
	builder.MarkBoolean(res)
	if aConstant {
		a, b = b, a
		bConstant = aConstant
		_b = _a
	}
	if bConstant {
		l := a.(expr.TermToRefactor)
		r := l
		oneMinusTwoB := big.NewInt(1)
		oneMinusTwoB.Sub(oneMinusTwoB, _b).Sub(oneMinusTwoB, _b)
		builder.addPlonkConstraint(l, r, res, builder.st.CoeffID(oneMinusTwoB), constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdMinusOne, builder.st.CoeffID(_b))
		return res
	}
	l := a.(expr.TermToRefactor)
	r := b.(expr.TermToRefactor)
	builder.addPlonkConstraint(l, r, res, constraint.CoeffIdMinusOne, constraint.CoeffIdMinusOne, constraint.CoeffIdTwo, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdZero)
	return res
}

// Or returns a | b
// a and b must be 0 or 1
func (builder *scs) Or(a, b frontend.Variable) frontend.Variable {

	builder.AssertIsBoolean(a)
	builder.AssertIsBoolean(b)

	_a, aConstant := builder.ConstantValue(a)
	_b, bConstant := builder.ConstantValue(b)

	if aConstant && bConstant {
		_a.Or(_a, _b)
		return _a
	}
	res := builder.newInternalVariable()
	builder.MarkBoolean(res)
	if aConstant {
		a, b = b, a
		_b = _a
		bConstant = aConstant
	}
	if bConstant {
		l := a.(expr.TermToRefactor)
		r := l

		one := big.NewInt(1)
		_b.Sub(_b, one)
		idl := builder.st.CoeffID(_b)
		builder.addPlonkConstraint(l, r, res, idl, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdOne, constraint.CoeffIdZero)
		return res
	}
	l := a.(expr.TermToRefactor)
	r := b.(expr.TermToRefactor)
	builder.addPlonkConstraint(l, r, res, constraint.CoeffIdMinusOne, constraint.CoeffIdMinusOne, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdZero)
	return res
}

// Or returns a & b
// a and b must be 0 or 1
func (builder *scs) And(a, b frontend.Variable) frontend.Variable {
	builder.AssertIsBoolean(a)
	builder.AssertIsBoolean(b)
	res := builder.Mul(a, b)
	builder.MarkBoolean(res)
	return res
}

// ---------------------------------------------------------------------------------------------
// Conditionals

// Select if b is true, yields i1 else yields i2
func (builder *scs) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	_b, bConstant := builder.ConstantValue(b)

	if bConstant {
		if !(_b.IsUint64() && (_b.Uint64() <= 1)) {
			panic(fmt.Sprintf("%s should be 0 or 1", _b.String()))
		}
		if _b.Uint64() == 0 {
			return i2
		}
		return i1
	}

	u := builder.Sub(i1, i2)
	l := builder.Mul(u, b)

	return builder.Add(l, i2)
}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (builder *scs) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {

	// vars, _ := builder.toVariables(b0, b1, i0, i1, i2, i3)
	// s0, s1 := vars[0], vars[1]
	// in0, in1, in2, in3 := vars[2], vars[3], vars[4], vars[5]

	// ensure that bits are actually bits. Adds no constraints if the variables
	// are already constrained.
	builder.AssertIsBoolean(b0)
	builder.AssertIsBoolean(b1)

	c0, b0IsConstant := builder.ConstantValue(b0)
	c1, b1IsConstant := builder.ConstantValue(b1)

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
	tmp1 := builder.Add(i3, i0)
	tmp1 = builder.Sub(tmp1, i2, i1)
	tmp1 = builder.Mul(tmp1, b1)
	tmp1 = builder.Add(tmp1, i1)
	tmp1 = builder.Sub(tmp1, i0)  // (1) tmp1 = s1 * (in3 - in2 - in1 + in0) + in1 - in0
	tmp2 := builder.Mul(tmp1, b0) // (2) tmp2 = tmp1 * s0
	res := builder.Sub(i2, i0)
	res = builder.Mul(res, b1)
	res = builder.Add(res, tmp2, i0) // (3) res = (v2 - v0) * s1 + tmp2 + in0

	return res

}

// IsZero returns 1 if a is zero, 0 otherwise
func (builder *scs) IsZero(i1 frontend.Variable) frontend.Variable {
	if a, ok := builder.ConstantValue(i1); ok {
		if !(a.IsUint64() && a.Uint64() == 0) {
			return 0
		}
		return 1
	}

	// x = 1/a 				// in a hint (x == 0 if a == 0)
	// m = -a*x + 1         // constrain m to be 1 if a == 0
	// a * m = 0            // constrain m to be 0 if a != 0
	a := i1.(expr.TermToRefactor)
	m := builder.newInternalVariable()

	// x = 1/a 				// in a hint (x == 0 if a == 0)
	x, err := builder.NewHint(hint.InvZero, 1, a)
	if err != nil {
		// the function errs only if the number of inputs is invalid.
		panic(err)
	}

	// m = -a*x + 1         // constrain m to be 1 if a == 0
	// a*x + m - 1 == 0
	builder.addPlonkConstraint(a,
		x[0].(expr.TermToRefactor),
		m,
		constraint.CoeffIdZero,
		constraint.CoeffIdZero,
		constraint.CoeffIdOne,
		constraint.CoeffIdOne,
		constraint.CoeffIdOne,
		constraint.CoeffIdMinusOne,
	)

	// a * m = 0            // constrain m to be 0 if a != 0
	builder.addPlonkConstraint(a, m, builder.zero(), constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdZero, constraint.CoeffIdZero)

	return m
}

// Cmp returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2
func (builder *scs) Cmp(i1, i2 frontend.Variable) frontend.Variable {

	bi1 := builder.ToBinary(i1, builder.cs.FieldBitLen())
	bi2 := builder.ToBinary(i2, builder.cs.FieldBitLen())

	var res frontend.Variable
	res = 0

	for i := builder.cs.FieldBitLen() - 1; i >= 0; i-- {

		iszeroi1 := builder.IsZero(bi1[i])
		iszeroi2 := builder.IsZero(bi2[i])

		i1i2 := builder.And(bi1[i], iszeroi2)
		i2i1 := builder.And(bi2[i], iszeroi1)

		n := builder.Select(i2i1, -1, 0)
		m := builder.Select(i1i2, 1, n)

		res = builder.Select(builder.IsZero(res), m, res)

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
func (builder *scs) Println(a ...frontend.Variable) {
	var log constraint.LogEntry

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		log.Caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	var sbb strings.Builder

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		if v, ok := arg.(expr.TermToRefactor); ok {

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, constraint.LinearExpression{builder.TOREFACTORMakeTerm(&builder.st.Coeffs[v.CID], v.VID)})
		} else {
			builder.printArg(&log, &sbb, arg)
		}
	}

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	log.Format = sbb.String()

	builder.cs.AddLog(log)
}

func (builder *scs) printArg(log *constraint.LogEntry, sbb *strings.Builder, a frontend.Variable) {

	leafCount, err := schema.Walk(a, tVariable, nil)
	count := leafCount.Public + leafCount.Secret

	// no variables in nested struct, we use fmt std print function
	if count == 0 || err != nil {
		sbb.WriteString(fmt.Sprint(a))
		return
	}

	sbb.WriteByte('{')
	printer := func(f schema.LeafInfo, tValue reflect.Value) error {
		count--
		sbb.WriteString(f.FullName())
		sbb.WriteString(": ")
		sbb.WriteString("%s")
		if count != 0 {
			sbb.WriteString(", ")
		}

		v := tValue.Interface().(expr.TermToRefactor)
		// we set limits to the linear expression, so that the log printer
		// can evaluate it before printing it
		log.ToResolve = append(log.ToResolve, constraint.LinearExpression{builder.TOREFACTORMakeTerm(&builder.st.Coeffs[v.CID], v.VID)})
		return nil
	}
	// ignoring error, printer() doesn't return errors
	_, _ = schema.Walk(a, tVariable, printer)
	sbb.WriteByte('}')
}

func (builder *scs) Compiler() frontend.Compiler {
	return builder
}

func scsBsb22CommitmentHintPlaceholder(*big.Int, []*big.Int, []*big.Int) error {
	return errors.New("placeholder - should never be called")
}

func (builder *scs) Commit(v ...frontend.Variable) (frontend.Variable, error) {

	committed := make([]int, len(v))
	// NOT THREAD SAFE. Recording constraint indexes
	for i, vI := range v { // TODO: Perf; If public, just hash it
		vIExpr := vI.(constraint.LinearExpression)
		if len(vIExpr) != 1 {
			return nil, errors.New("can only commit to single terms") // TODO: Create a wire in this case
		}
		committed[i] = builder.cs.GetNbConstraints()
		builder.cs.AddConstraint(constraint.SparseR1C{L: vIExpr[0], Commitment: constraint.COMMITTED})
	}
	outs, err := builder.NewHint(scsBsb22CommitmentHintPlaceholder, 1, v...)
	if err != nil {
		return nil, err
	}
	commitmentVar := outs[0]

	commitmentConstraintIndex := builder.cs.GetNbConstraints()
	builder.cs.AddConstraint(constraint.SparseR1C{L: commitmentVar.(constraint.LinearExpression)[0], Commitment: constraint.COMMITMENT}) // value will be injected later

	return outs[0], builder.cs.AddCommitment(constraint.Commitment{
		HintID:          hint.UUID(scsBsb22CommitmentHintPlaceholder),
		CommitmentIndex: commitmentConstraintIndex,
		Committed:       committed,
	})
}
