package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type variableEquality[T FieldParams] struct {
	Modulus Element[T]
	A, B    Element[T]
}

func (c *variableEquality[T]) Define(api frontend.API) error {
	v, err := NewVariableModulus[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	v.ModAssertIsEqual(&c.A, &c.B, &c.Modulus)
	return nil
}

func TestVariableEquality(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171", 10)
	a := big.NewInt(10)
	b := new(big.Int).Add(a, modulus)
	circuit := &variableEquality[Any4096Field]{}
	assignment := &variableEquality[Any4096Field]{
		Modulus: ValueOf[Any4096Field](modulus),
		A:       ValueOf[Any4096Field](a),
		B:       ValueOf[Any4096Field](b),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableAddition[T FieldParams] struct {
	Modulus  Element[T]
	A, B     Element[T]
	Expected Element[T]
}

func (c *variableAddition[T]) Define(api frontend.API) error {
	v, err := NewVariableModulus[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := v.ModAdd(&c.A, &c.B, &c.Modulus)
	v.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableAddition(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171", 10)
	circuit := &variableAddition[Any4096Field]{}
	assignment := &variableAddition[Any4096Field]{
		Modulus:  ValueOf[Any4096Field](modulus),
		A:        ValueOf[Any4096Field](10),
		B:        ValueOf[Any4096Field](20),
		Expected: ValueOf[Any4096Field](30),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableSubtraction[T FieldParams] struct {
	Modulus  Element[T]
	A, B     Element[T]
	Expected Element[T]
}

func (c *variableSubtraction[T]) Define(api frontend.API) error {
	v, err := NewVariableModulus[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := v.Sub(&c.A, &c.B, &c.Modulus)
	v.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableSubtraction(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171", 10)
	circuit := &variableSubtraction[Any4096Field]{}
	res := new(big.Int).Sub(modulus, big.NewInt(10))
	assignment := &variableSubtraction[Any4096Field]{
		Modulus:  ValueOf[Any4096Field](modulus),
		A:        ValueOf[Any4096Field](10),
		B:        ValueOf[Any4096Field](20),
		Expected: ValueOf[Any4096Field](res),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableMultiplication[T FieldParams] struct {
	Modulus  Element[T]
	A, B     Element[T]
	Expected Element[T]
}

func (c *variableMultiplication[T]) Define(api frontend.API) error {
	v, err := NewVariableModulus[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := v.ModMul(&c.A, &c.B, &c.Modulus)
	v.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableMultiplication(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171", 10)
	a, _ := rand.Int(rand.Reader, modulus)
	b, _ := rand.Int(rand.Reader, modulus)
	exp := new(big.Int).Mul(a, b)
	exp.Mod(exp, modulus)
	circuit := &variableMultiplication[Any4096Field]{}
	assignment := &variableMultiplication[Any4096Field]{
		Modulus:  ValueOf[Any4096Field](modulus),
		A:        ValueOf[Any4096Field](a),
		B:        ValueOf[Any4096Field](b),
		Expected: ValueOf[Any4096Field](exp),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

type variableExp[T FieldParams] struct {
	Modulus  Element[T]
	Base     Element[T]
	Exp      Element[T]
	Expected Element[T]
}

func (c *variableExp[T]) Define(api frontend.API) error {
	v, err := NewVariableModulus[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := v.ModExp(&c.Base, &c.Exp, &c.Modulus)
	v.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableExp(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	base, _ := rand.Int(rand.Reader, modulus)
	exp, _ := rand.Int(rand.Reader, modulus)
	expected := new(big.Int).Exp(base, exp, modulus)
	circuit := &variableExp[Any4096Field]{}
	assignment := &variableExp[Any4096Field]{
		Modulus:  ValueOf[Any4096Field](modulus),
		Base:     ValueOf[Any4096Field](base),
		Exp:      ValueOf[Any4096Field](exp),
		Expected: ValueOf[Any4096Field](expected),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}
