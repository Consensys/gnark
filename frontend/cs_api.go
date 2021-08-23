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
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark/internal/backend/compiled"

	"github.com/consensys/gnark-crypto/ecc"
	frbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	frbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	frbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
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
// TODO the function should take an interface
func (cs *ConstraintSystem) Inverse(v Variable) Variable {

	v.assertIsSet()

	// allocate resulting variable
	res := cs.newInternalVariable()

	cs.constraints = append(cs.constraints, newR1C(v, res, cs.one()))

	return res
}

// Div returns res = i1 / i2
func (cs *ConstraintSystem) Div(i1, i2 interface{}) Variable {

	// allocate resulting variable
	res := cs.newInternalVariable()

	// O
	switch t1 := i1.(type) {
	case Variable:
		t1.assertIsSet()
		switch t2 := i2.(type) {
		case Variable:
			t2.assertIsSet()
			cs.constraints = append(cs.constraints, newR1C(t2, res, t1))
		default:
			tmp := cs.Constant(t2)
			cs.constraints = append(cs.constraints, newR1C(tmp, res, t1))
		}
	default:
		switch t2 := i2.(type) {
		case Variable:
			t2.assertIsSet()
			tmp := cs.Constant(t1)
			cs.constraints = append(cs.constraints, newR1C(t2, res, tmp))
		default:
			tmp1 := cs.Constant(t1)
			tmp2 := cs.Constant(t2)
			cs.constraints = append(cs.constraints, newR1C(tmp2, res, tmp1))
		}
	}

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
func (cs *ConstraintSystem) IsZero(a Variable, id ecc.ID) Variable {

	var expo big.Int
	switch id {
	case ecc.BN254:
		expo.Set(frbn254.Modulus())
	case ecc.BLS12_381:
		expo.Set(frbls12381.Modulus())
	case ecc.BLS12_377:
		expo.Set(frbls12377.Modulus())
	case ecc.BW6_761:
		expo.Set(frbw6761.Modulus())
	case ecc.BLS24_315:
		expo.Set(frbls24315.Modulus())
	default:
		panic("not implemented")
	}

	res := cs.Constant(1)
	expoBytes := expo.Bytes()
	nbBits := len(expoBytes) * 8
	for i := nbBits - 1; i >= 1; i-- { // up to i-1 because we go up to q-1
		res = cs.Mul(res, res)
		if expo.Bit(i) == 1 {
			res = cs.Mul(res, a)
		}
	}
	res = cs.Mul(res, res) // final squaring
	res = cs.Sub(1, res)
	return res
}

// ToBinary unpacks a variable in binary, n is the number of bits of the variable
//
// The result in in little endian (first bit= lsb)
func (cs *ConstraintSystem) ToBinary(a Variable, nbBits int) []Variable {
	// ensure a is set
	a.assertIsSet()

	// allocate the resulting variables and bit-constraint them
	b := make([]Variable, nbBits)
	for i := 0; i < nbBits; i++ {
		b[i] = cs.newInternalVariable()
		cs.AssertIsBoolean(b[i])
	}

	// here what we do is we add a single constraint where
	// Σ (2**i * b[i]) == a
	var c big.Int
	c.Set(bOne)

	var Σbi Variable
	Σbi.linExp = make(compiled.LinearExpression, nbBits)

	for i := 0; i < nbBits; i++ {
		Σbi.linExp[i] = cs.makeTerm(Wire{compiled.Internal, b[i].id, nil}, &c)
		c.Lsh(&c, 1)
	}

	// record the constraint Σ (2**i * b[i]) == a
	cs.constraints = append(cs.constraints, newR1C(Σbi, cs.one(), a, compiled.BinaryDec))
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
	c.Set(bOne)

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
		cs.constraints = append(cs.constraints, newR1C(b, v, w))
		return res
	default:
		switch t2 := i2.(type) {
		case Variable:
			t2.assertIsSet()
			res = cs.newInternalVariable()
			v := cs.Sub(t1, t2)  // no constraint is recorded
			w := cs.Sub(res, t2) // no constraint is recorded
			cs.constraints = append(cs.constraints, newR1C(b, v, w))
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

// creates a string formatted to display correctly a variable, from its linear expression representation
// (i.e. the linear expression leading to it)
func (cs *ConstraintSystem) buildLogEntryFromVariable(v Variable) logEntry {

	var res logEntry
	var sbb strings.Builder
	sbb.Grow(len(v.linExp) * len(" + (xx + xxxxxxxxxxxx"))

	for i := 0; i < len(v.linExp); i++ {
		if i > 0 {
			sbb.WriteString(" + ")
		}
		c := cs.coeffs[v.linExp[i].CoeffID()]
		sbb.WriteString(fmt.Sprintf("(%%s * %s)", c.String()))
	}
	res.format = sbb.String()
	res.toResolve = v.linExp.Clone()
	return res
}

// AssertIsEqual adds an assertion in the constraint system (i1 == i2)
func (cs *ConstraintSystem) AssertIsEqual(i1, i2 interface{}) {

	// encoded as L * R == O
	// set L = i1
	// set R = 1
	// set O = i2

	// we don't do just "cs.Sub(i1,i2)" to allow proper logging
	debugInfo := logEntry{}

	l := cs.Constant(i1) // no constraint is recorded
	r := cs.Constant(1)  // no constraint is recorded
	o := cs.Constant(i2) // no constraint is recorded

	// build log
	var sbb strings.Builder
	sbb.WriteString("[")
	lhs := cs.buildLogEntryFromVariable(l)
	sbb.WriteString(lhs.format)
	debugInfo.toResolve = lhs.toResolve
	sbb.WriteString(" != ")
	rhs := cs.buildLogEntryFromVariable(o)
	sbb.WriteString(rhs.format)
	debugInfo.toResolve = append(debugInfo.toResolve, rhs.toResolve...)
	sbb.WriteString("]")

	// get call stack
	sbb.WriteString("error AssertIsEqual")
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	cs.addAssertion(newR1C(l, r, o), debugInfo)
}

// markBoolean marks the variable as boolean and return true
// if a constraint was added, false if the variable was already
// constrained as a boolean
func (cs *ConstraintSystem) markBoolean(v Variable) bool {
	switch v.visibility {
	case compiled.Internal:
		if _, ok := cs.internal.booleans[v.id]; ok {
			return false
		}
		cs.internal.booleans[v.id] = struct{}{}
	case compiled.Secret:
		if _, ok := cs.secret.booleans[v.id]; ok {
			return false
		}
		cs.secret.booleans[v.id] = struct{}{}
	case compiled.Public:
		if _, ok := cs.public.booleans[v.id]; ok {
			return false
		}
		cs.public.booleans[v.id] = struct{}{}
	default:
		panic("not implemented")
	}
	return true
}

// AssertIsBoolean adds an assertion in the constraint system (v == 0 || v == 1)
func (cs *ConstraintSystem) AssertIsBoolean(v Variable) {

	v.assertIsSet()

	if !cs.markBoolean(v) {
		return // variable is already constrained
	}

	_v := cs.Sub(1, v)  // no variable is recorded in the cs
	o := cs.Constant(0) // no variable is recorded in the cs

	// prepare debug info to be displayed in case the constraint is not solved
	debugInfo := logEntry{
		toResolve: nil,
	}
	var sbb strings.Builder
	sbb.WriteString("error AssertIsBoolean")
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	cs.addAssertion(newR1C(v, _v, o), debugInfo)
}

// AssertIsLessOrEqual adds assertion in constraint system  (v <= bound)
//
// bound can be a constant or a Variable
//
// derived from:
// https://github.com/zcash/zips/blOoutputb/master/protocol/protocol.pdf
func (cs *ConstraintSystem) AssertIsLessOrEqual(v Variable, bound interface{}) {

	v.assertIsSet()

	switch b := bound.(type) {
	case Variable:
		b.assertIsSet()
		cs.mustBeLessOrEqVar(v, b)
	default:
		cs.mustBeLessOrEqCst(v, FromInterface(b))
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqVar(w, bound Variable) {

	// prepare debug info to be displayed in case the constraint is not solved
	dbgInfoW := cs.buildLogEntryFromVariable(w)
	dbgInfoBound := cs.buildLogEntryFromVariable(bound)
	var sbb strings.Builder
	var debugInfo logEntry
	sbb.WriteString(dbgInfoW.format)
	sbb.WriteString(" <= ")
	sbb.WriteString(dbgInfoBound.format)
	debugInfo.toResolve = make([]compiled.Term, len(dbgInfoW.toResolve)+len(dbgInfoBound.toResolve))
	copy(debugInfo.toResolve[:], dbgInfoW.toResolve)
	copy(debugInfo.toResolve[len(dbgInfoW.toResolve):], dbgInfoBound.toResolve)

	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	const nbBits = 256

	binw := cs.ToBinary(w, nbBits)
	binbound := cs.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = cs.Constant(1)

	zero := cs.Constant(0)

	for i := nbBits - 1; i >= 0; i-- {

		p1 := cs.Mul(p[i+1], binw[i])
		p[i] = cs.Select(binbound[i], p1, p[i+1])
		t := cs.Select(binbound[i], zero, p[i+1])

		l := cs.one()
		l = cs.Sub(l, t)       // no constraint is recorded
		l = cs.Sub(l, binw[i]) // no constraint is recorded

		r := binw[i]

		o := cs.Constant(0) // no constraint is recorded

		cs.addAssertion(newR1C(l, r, o), debugInfo)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqCst(v Variable, bound big.Int) {

	// prepare debug info to be displayed in case the constraint is not solved
	dbgInfoW := cs.buildLogEntryFromVariable(v)
	var sbb strings.Builder
	var debugInfo logEntry
	sbb.WriteString(dbgInfoW.format)
	sbb.WriteString(" <= ")
	sbb.WriteString(bound.String())

	debugInfo.toResolve = dbgInfoW.toResolve

	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	// TODO store those constant elsewhere (for the moment they don't depend on the base curve, but that might change)
	const nbBits = 256
	const nbWords = 4
	const wordSize = 64

	vBits := cs.ToBinary(v, nbBits)
	boundBits := bound.Bits()
	l := len(boundBits)
	if len(boundBits) < nbWords {
		for i := 0; i < nbWords-l; i++ {
			boundBits = append(boundBits, big.Word(0))
		}
	}

	p := make([]Variable, nbBits+1)

	p[nbBits] = cs.Constant(1)
	for i := nbWords - 1; i >= 0; i-- {
		for j := 0; j < wordSize; j++ {
			b := (boundBits[i] >> (wordSize - 1 - j)) & 1
			if b == 0 {
				p[(i+1)*wordSize-1-j] = p[(i+1)*wordSize-j]

				l := cs.one()
				l = cs.Sub(l, p[(i+1)*wordSize-j])       // no constraint is recorded
				l = cs.Sub(l, vBits[(i+1)*wordSize-1-j]) // no constraint is recorded

				r := vBits[(i+1)*wordSize-1-j]
				o := cs.Constant(0)
				cs.addAssertion(newR1C(l, r, o), debugInfo)

			} else {
				p[(i+1)*wordSize-1-j] = cs.Mul(p[(i+1)*wordSize-j], vBits[(i+1)*wordSize-1-j])
			}
		}
	}
}

// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a Variable, its value will be resolved avec R1CS.Solve() method is called
func (cs *ConstraintSystem) Println(a ...interface{}) {
	var sbb strings.Builder

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	// for each argument, if it is a circuit structure and contains variable
	// we add the variables in the logEntry.toResolve part, and add %s to the format string in the log entry
	// if it doesn't contain variable, call fmt.Sprint(arg) instead
	entry := logEntry{}

	// this is call recursively on the arguments using reflection on each argument
	foundVariable := false

	var handler logValueHandler = func(name string, tInput reflect.Value) {

		v := tInput.Interface().(Variable)

		// if the variable is only in linExp form, we allocate it
		_v := cs.allocate(v)

		entry.toResolve = append(entry.toResolve, compiled.Pack(_v.id, 0, _v.visibility))

		if name == "" {
			sbb.WriteString("%s")
		} else {
			sbb.WriteString(fmt.Sprintf("%s: %%s ", name))
		}

		foundVariable = true
	}

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		foundVariable = false
		parseLogValue(arg, "", handler)
		if !foundVariable {
			sbb.WriteString(fmt.Sprint(arg))
		}
	}
	sbb.WriteByte('\n')

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	entry.format = sbb.String()

	cs.logs = append(cs.logs, entry)
}
