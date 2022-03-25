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

package test

import (
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
)

// engine implements frontend.API
//
// it is used for a faster verification of witness in tests
// and more importantly, for fuzzing purposes
//
// it converts the inputs to the API to big.Int (after a mod reduce using the curve base field)
type engine struct {
	backendID backend.ID
	curveID   ecc.ID
	opt       backend.ProverConfig
	// mHintsFunctions map[hint.ID]hintFunction
}

// IsSolved returns an error if the test execution engine failed to execute the given circuit
// with provided witness as input.
//
// The test execution engine implements frontend.API using big.Int operations.
//
// This is an experimental feature.
func IsSolved(circuit, witness frontend.Circuit, curveID ecc.ID, b backend.ID, opts ...backend.ProverOption) (err error) {
	// apply options
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return err
	}

	e := &engine{backendID: b, curveID: curveID, opt: opt}
	if opt.Force {
		panic("ignoring errors in test.Engine is not supported")
	}

	// TODO handle opt.LoggerOut ?

	// we clone the circuit, in case the circuit has some attributes it uses in its Define function
	// set by the user.
	// then, we set all the variables values to the ones from the witness

	// clone the circuit
	c := shallowClone(circuit)

	// set the witness values
	copyWitness(c, witness)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, string(debug.Stack()))
		}
	}()

	err = c.Define(e)

	return
}

func (e *engine) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	b1.Add(&b1, &b2)
	for i := 0; i < len(in); i++ {
		bn := e.toBigInt(in[i])
		b1.Add(&b1, &bn)
	}
	b1.Mod(&b1, e.modulus())
	return b1
}

func (e *engine) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	b1.Sub(&b1, &b2)
	for i := 0; i < len(in); i++ {
		bn := e.toBigInt(in[i])
		b1.Sub(&b1, &bn)
	}
	b1.Mod(&b1, e.modulus())
	return b1
}

func (e *engine) Neg(i1 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(i1)
	b1.Neg(&b1)
	b1.Mod(&b1, e.modulus())
	return b1
}

func (e *engine) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	b1.Mul(&b1, &b2).Mod(&b1, e.modulus())
	for i := 0; i < len(in); i++ {
		bn := e.toBigInt(in[i])
		b1.Mul(&b1, &bn).Mod(&b1, e.modulus())
	}
	return b1
}

func (e *engine) Div(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b2.ModInverse(&b2, e.modulus()) == nil {
		panic("no inverse")
	}
	b2.Mul(&b1, &b2).Mod(&b2, e.modulus())
	return b2
}

func (e *engine) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.IsUint64() && b2.IsUint64() && b1.Uint64() == 0 && b2.Uint64() == 0 {
		return 0
	}
	if b2.ModInverse(&b2, e.modulus()) == nil {
		panic("no inverse")
	}
	b2.Mul(&b1, &b2).Mod(&b2, e.modulus())
	return b2
}

func (e *engine) Inverse(i1 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(i1)
	if b1.ModInverse(&b1, e.modulus()) == nil {
		panic("no inverse")
	}
	return b1
}

func (e *engine) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	nbBits := e.bitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	b1 := e.toBigInt(i1)

	if b1.BitLen() > nbBits {
		panic(fmt.Sprintf("[ToBinary] decomposing %s (bitLen == %d) with %d bits", b1.String(), b1.BitLen(), nbBits))
	}

	r := make([]frontend.Variable, nbBits)
	ri := make([]frontend.Variable, nbBits)
	for i := 0; i < len(r); i++ {
		r[i] = (b1.Bit(i))
		ri[i] = r[i]
	}

	// this is a sanity check, it should never happen
	value := e.toBigInt(e.FromBinary(ri...))
	if value.Cmp(&b1) != 0 {

		panic(fmt.Sprintf("[ToBinary] decomposing %s (bitLen == %d) with %d bits reconstructs into %s", b1.String(), b1.BitLen(), nbBits, value.String()))
	}
	return r
}

func (e *engine) FromBinary(v ...frontend.Variable) frontend.Variable {
	bits := make([]big.Int, len(v))
	for i := 0; i < len(v); i++ {
		bits[i] = e.toBigInt(v[i])
		e.mustBeBoolean(&bits[i])
	}

	// Σ (2**i * bits[i]) == r
	var c, r big.Int
	c.SetUint64(1)

	for i := 0; i < len(bits); i++ {
		bits[i].Mul(&bits[i], &c)
		r.Add(&r, &bits[i])
		c.Lsh(&c, 1)
	}
	r.Mod(&r, e.modulus())

	return r
}

func (e *engine) Xor(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(&b1)
	e.mustBeBoolean(&b2)
	b1.Xor(&b1, &b2)
	return b1
}

func (e *engine) Or(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(&b1)
	e.mustBeBoolean(&b2)
	b1.Or(&b1, &b2)
	return b1
}

func (e *engine) And(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(&b1)
	e.mustBeBoolean(&b2)
	b1.And(&b1, &b2)
	return b1
}

// Select if b is true, yields i1 else yields i2
func (e *engine) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(b)
	e.mustBeBoolean(&b1)

	if b1.Uint64() == 1 {
		return e.toBigInt(i1)
	}
	return (e.toBigInt(i2))
}

// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
// and i3 if b0=b1=1.
func (e *engine) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	s0 := e.toBigInt(b0)
	s1 := e.toBigInt(b1)
	e.mustBeBoolean(&s0)
	e.mustBeBoolean(&s1)
	lookup := new(big.Int).Lsh(&s1, 1)
	lookup.Or(lookup, &s0)
	return e.toBigInt([]frontend.Variable{i0, i1, i2, i3}[lookup.Uint64()])
}

// IsZero returns 1 if a is zero, 0 otherwise
func (e *engine) IsZero(i1 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(i1)

	if b1.IsUint64() && b1.Uint64() == 0 {
		return 1
	}

	return (0)
}

// Cmp returns 1 if i1>i2, 0 if i1==i2, -1 if i1<i2
func (e *engine) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(i1)
	b2 := e.toBigInt(i2)
	return e.toBigInt(b1.Cmp(&b2))
}

func (e *engine) AssertIsEqual(i1, i2 frontend.Variable) {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Cmp(&b2) != 0 {
		panic(fmt.Sprintf("[assertIsEqual] %s == %s", b1.String(), b2.String()))
	}
}

func (e *engine) AssertIsDifferent(i1, i2 frontend.Variable) {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Cmp(&b2) == 0 {
		panic(fmt.Sprintf("[assertIsDifferent] %s != %s", b1.String(), b2.String()))
	}
}

func (e *engine) AssertIsBoolean(i1 frontend.Variable) {
	b1 := e.toBigInt(i1)
	e.mustBeBoolean(&b1)
}

func (e *engine) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {

	bValue := e.toBigInt(bound)

	if bValue.Sign() == -1 {
		panic(fmt.Sprintf("[assertIsLessOrEqual] bound (%s) must be positive", bValue.String()))
	}

	b1 := e.toBigInt(v)
	if b1.Cmp(&bValue) == 1 {
		panic(fmt.Sprintf("[assertIsLessOrEqual] %s > %s", b1.String(), bValue.String()))
	}
}

func (e *engine) Println(a ...frontend.Variable) {
	var sbb strings.Builder
	sbb.WriteString("(test.engine) ")

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	for i := 0; i < len(a); i++ {
		v := e.toBigInt(a[i])
		sbb.WriteString(v.String())
		sbb.WriteByte(' ')
	}
	fmt.Println(sbb.String())
}

func (e *engine) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {

	if nbOutputs <= 0 {
		return nil, fmt.Errorf("hint function must return at least one output")
	}

	in := make([]*big.Int, len(inputs))

	for i := 0; i < len(inputs); i++ {
		v := e.toBigInt(inputs[i])
		in[i] = &v
	}
	res := make([]*big.Int, nbOutputs)
	for i := range res {
		res[i] = new(big.Int)
	}

	err := f(e.curveID, in, res)

	if err != nil {
		panic("NewHint: " + err.Error())
	}

	out := make([]frontend.Variable, len(res))
	for i := range res {
		out[i] = res[i]
	}

	return out, nil
}

// IsConstant returns true if v is a constant known at compile time
func (e *engine) IsConstant(v frontend.Variable) bool {
	// TODO @gbotrel this is a problem. if a circuit component has 2 code path depending
	// on constant parameter, it will never be tested in the test engine
	// we may want to call IsSolved twice, and return false to all IsConstant on one of the runs
	return true
}

// ConstantValue returns the big.Int value of v
// will panic if v.IsConstant() == false
func (e *engine) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	r := e.toBigInt(v)
	return &r, true
}

func (e *engine) IsBoolean(v frontend.Variable) bool {
	r := e.toBigInt(v)
	return r.IsUint64() && r.Uint64() <= 1
}

func (e *engine) MarkBoolean(v frontend.Variable) {
	if !e.IsBoolean(v) {
		panic("mark boolean a non-boolean value")
	}
}

func (e *engine) Tag(name string) frontend.Tag {
	// do nothing, we don't measure constraints with the test engine
	return frontend.Tag{Name: name}
}

func (e *engine) AddCounter(from, to frontend.Tag) {
	// do nothing, we don't measure constraints with the test engine
}

func (e *engine) toBigInt(i1 frontend.Variable) big.Int {
	b := utils.FromInterface(i1)
	b.Mod(&b, e.modulus())
	return b
}

// bitLen returns the number of bits needed to represent a fr.Element
func (e *engine) bitLen() int {
	return e.curveID.Info().Fr.Bits
}

func (e *engine) mustBeBoolean(b *big.Int) {
	if !b.IsUint64() || !(b.Uint64() == 0 || b.Uint64() == 1) {
		panic(fmt.Sprintf("[assertIsBoolean] %s", b.String()))
	}
}

func (e *engine) modulus() *big.Int {
	return e.curveID.Info().Fr.Modulus()
}

func (e *engine) Curve() ecc.ID {
	return e.curveID
}

func (e *engine) Backend() backend.ID {
	return e.backendID
}

// shallowClone clones given circuit
// this is actually a shallow copy → if the circuits contains maps or slices
// only the reference is copied.
func shallowClone(circuit frontend.Circuit) frontend.Circuit {

	cValue := reflect.ValueOf(circuit).Elem()
	newCircuit := reflect.New(cValue.Type())
	newCircuit.Elem().Set(cValue)

	circuitCopy, ok := newCircuit.Interface().(frontend.Circuit)
	if !ok {
		panic("couldn't clone the circuit")
	}

	if !reflect.DeepEqual(circuitCopy, circuit) {
		panic("clone failed")
	}

	return circuitCopy
}

func copyWitness(to, from frontend.Circuit) {
	var wValues []interface{}

	var collectHandler schema.LeafHandler = func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if visibility == schema.Secret || visibility == schema.Public {
			if v == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", name)
			}
			wValues = append(wValues, v)
		}
		return nil
	}
	if _, err := schema.Parse(from, tVariable, collectHandler); err != nil {
		panic(err)
	}

	i := 0
	var setHandler schema.LeafHandler = func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		if visibility == schema.Secret || visibility == schema.Public {
			tInput.Set(reflect.ValueOf((wValues[i])))
			i++
		}
		return nil
	}
	// this can't error.
	_, _ = schema.Parse(to, tVariable, setHandler)

}

func (e *engine) Compiler() frontend.Compiler {
	return e
}
