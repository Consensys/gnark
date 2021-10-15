package test

import (
	"fmt"
	"math/big"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// engine implements frontend.API
//
// it is used for a faster verification of witness in tests
// and more importantly, for fuzzing purposes
//
// it converts the inputs to the API to big.Int (after a mod reduce using the curve base field)
type engine struct {
	curveID ecc.ID
}

func isSolved(circuit, witness frontend.Circuit, curveID ecc.ID) (err error) {
	e := &engine{curveID: curveID}

	// we clone the circuit, in case the circuit has some attributes it uses in its Define function
	// set by the user.
	// then, we set all the variables values to the ones from the witness

	// clone the circuit
	cValue := reflect.ValueOf(circuit).Elem()
	newCircuit := reflect.New(cValue.Type())
	newCircuit.Elem().Set(cValue)

	c, ok := newCircuit.Interface().(frontend.Circuit)
	if !ok {
		panic("couldn't clone the circuit")
	}

	// set the witness values
	copyWitness(c, witness)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, string(debug.Stack()))
		}
	}()

	err = c.Define(curveID, e)

	// we clear the values, in case our clone earlier copied somes slices or pointers
	clearValues(c)

	return
}

func (e *engine) Add(i1, i2 interface{}, in ...interface{}) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	b1.Add(&b1, &b2)
	for i := 0; i < len(in); i++ {
		bn := e.toBigInt(in[i])
		b1.Add(&b1, &bn)
	}
	b1.Mod(&b1, e.modulus())
	return frontend.Value(b1)
}

func (e *engine) Sub(i1, i2 interface{}) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	b1.Sub(&b1, &b2).Mod(&b1, e.modulus())
	return frontend.Value(b1)
}

func (e *engine) Neg(i1 interface{}) frontend.Variable {
	b1 := e.toBigInt(i1)
	b1.Neg(&b1)
	b1.Mod(&b1, e.modulus())
	return frontend.Value(b1)
}

func (e *engine) Mul(i1, i2 interface{}, in ...interface{}) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	b1.Mul(&b1, &b2).Mod(&b1, e.modulus())
	for i := 0; i < len(in); i++ {
		bn := e.toBigInt(in[i])
		b1.Mul(&b1, &bn).Mod(&b1, e.modulus())
	}
	return frontend.Value(b1)
}

func (e *engine) Div(i1, i2 interface{}) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b2.ModInverse(&b2, e.modulus()) == nil {
		panic("no inverse")
	}
	b2.Mul(&b1, &b2).Mod(&b2, e.modulus())
	return frontend.Value(b2)
}

func (e *engine) Inverse(v frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(v)
	if b1.ModInverse(&b1, e.modulus()) == nil {
		panic("no inverse")
	}
	return frontend.Value(b1)
}

func (e *engine) ToBinary(a frontend.Variable, n ...int) []frontend.Variable {
	nbBits := e.bitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("invalid n")
		}
	}

	b1 := e.toBigInt(a)
	r := make([]frontend.Variable, nbBits)
	for i := 0; i < len(r); i++ {
		r[i] = frontend.Value(b1.Bit(i))
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

	return frontend.Value(r)
}

func (e *engine) Xor(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(&b1)
	e.mustBeBoolean(&b2)
	b1.Xor(&b1, &b2)
	return frontend.Value(b1)
}

func (e *engine) Or(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(&b1)
	e.mustBeBoolean(&b2)
	b1.Or(&b1, &b2)
	return frontend.Value(b1)
}

func (e *engine) And(i1, i2 frontend.Variable) frontend.Variable {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	e.mustBeBoolean(&b1)
	e.mustBeBoolean(&b2)
	b1.And(&b1, &b2)
	return frontend.Value(b1)
}

// Select if b is true, yields i1 else yields i2
func (e *engine) Select(b frontend.Variable, i1, i2 interface{}) frontend.Variable {
	b1 := e.toBigInt(b)
	e.mustBeBoolean(&b1)

	if b1.Uint64() == 1 {
		return frontend.Value(e.toBigInt(i1))
	}
	return frontend.Value(e.toBigInt(i2))
}

// IsZero returns 1 if a is zero, 0 otherwise
func (e *engine) IsZero(a frontend.Variable) frontend.Variable {
	b1 := e.toBigInt(a)

	if b1.IsUint64() && b1.Uint64() == 0 {
		return frontend.Value(1)
	}

	return frontend.Value(0)
}

func (e *engine) Constant(input interface{}) frontend.Variable {
	return frontend.Value(e.toBigInt(input))
}

func (e *engine) AssertIsEqual(i1, i2 interface{}) {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Cmp(&b2) != 0 {
		panic("AssertIsEqual: b1 != b2")
	}
}

func (e *engine) AssertIsDifferent(i1, i2 interface{}) {
	b1, b2 := e.toBigInt(i1), e.toBigInt(i2)
	if b1.Cmp(&b2) == 0 {
		panic("AssertIsDifferent: b1 == b2")
	}
}

func (e *engine) AssertIsBoolean(v frontend.Variable) {
	b1 := e.toBigInt(v)
	e.mustBeBoolean(&b1)
}

func (e *engine) AssertIsLessOrEqual(v frontend.Variable, bound interface{}) {
	// note: here we don't do a mod reduce on the bound.
	var bValue big.Int
	if v, ok := bound.(frontend.Variable); ok {
		bValue = frontend.FromInterface(v.WitnessValue)
	} else {
		bValue = frontend.FromInterface(bound)
	}

	b1 := e.toBigInt(v)
	if b1.Cmp(&bValue) == 1 {
		panic("AssertIsLessOrEqual: b1 > bound")
	}
}

func (e *engine) Println(a ...interface{}) {
	var sbb strings.Builder

	for i := 0; i < len(a); i++ {
		if v, ok := a[i].(frontend.Variable); ok {
			b := e.toBigInt(v)
			sbb.WriteString(b.String())
		} else {
			sbb.WriteString(fmt.Sprint(a[i]))
		}
	}
	fmt.Println(sbb.String())
}

func (e *engine) toBigInt(i1 interface{}) big.Int {
	if v1, ok := i1.(frontend.Variable); ok {
		return v1.GetWitnessValue(e.curveID)
	}
	return frontend.FromInterface(i1)
}

// bitLen returns the number of bits needed to represent a fr.Element
func (e *engine) bitLen() int {
	switch e.curveID {
	case ecc.BN254:
		return fr_bn254.Bits
	case ecc.BLS12_377:
		return fr_bls12377.Bits
	case ecc.BLS12_381:
		return fr_bls12381.Bits
	case ecc.BW6_761:
		return fr_bw6761.Bits
	case ecc.BLS24_315:
		return fr_bls24315.Bits
	default:
		panic("curve not implemented")
	}
}

func (e *engine) mustBeBoolean(b *big.Int) {
	if !b.IsUint64() || !(b.Uint64() == 0 || b.Uint64() == 1) {
		panic(b.String() + "is not a boolean value")
	}
}

func (e *engine) modulus() *big.Int {
	switch e.curveID {
	case ecc.BN254:
		return fr_bn254.Modulus()
	case ecc.BLS12_377:
		return fr_bls12377.Modulus()
	case ecc.BLS12_381:
		return fr_bls12381.Modulus()
	case ecc.BW6_761:
		return fr_bw6761.Modulus()
	case ecc.BLS24_315:
		return fr_bls24315.Modulus()
	default:
		panic("curve not implemented")
	}
}

func copyWitness(to, from frontend.Circuit) {
	var wValues []interface{}

	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if visibility == compiled.Secret || visibility == compiled.Public {
			if v.WitnessValue == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", name)
			}
			wValues = append(wValues, v.WitnessValue)
		}
		return nil
	}
	if err := parser.Visit(from, "", compiled.Unset, collectHandler, reflect.TypeOf(frontend.Variable{})); err != nil {
		panic(err)
	}

	i := 0
	var setHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Secret || visibility == compiled.Public {
			tInput.Set(reflect.ValueOf(frontend.Value(wValues[i])))
			i++
		}
		return nil
	}
	parser.Visit(to, "", compiled.Unset, setHandler, reflect.TypeOf(frontend.Variable{}))

}

func clearValues(c frontend.Circuit) {
	var setHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Secret || visibility == compiled.Public {
			tInput.Set(reflect.ValueOf(frontend.Value(nil)))
		}
		return nil
	}
	parser.Visit(c, "", compiled.Unset, setHandler, reflect.TypeOf(frontend.Variable{}))
}
