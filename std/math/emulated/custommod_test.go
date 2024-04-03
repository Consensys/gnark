package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type variableEquality[T FieldParams] struct {
	Modulus Element[T]
	A, B    Element[T]
}

func (c *variableEquality[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	f.ModAssertIsEqual(&c.A, &c.B, &c.Modulus)
	return nil
}

func TestVariableEquality(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	a := big.NewInt(10)
	b := new(big.Int).Add(a, modulus)
	circuit := &variableEquality[emparams.Mod1e512]{}
	assignment := &variableEquality[emparams.Mod1e512]{
		Modulus: ValueOf[emparams.Mod1e512](modulus),
		A:       ValueOf[emparams.Mod1e512](a),
		B:       ValueOf[emparams.Mod1e512](b),
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
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModAdd(&c.A, &c.B, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableAddition(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	circuit := &variableAddition[emparams.Mod1e512]{}
	assignment := &variableAddition[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		A:        ValueOf[emparams.Mod1e512](10),
		B:        ValueOf[emparams.Mod1e512](20),
		Expected: ValueOf[emparams.Mod1e512](30),
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
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.modSub(&c.A, &c.B, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableSubtraction(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	circuit := &variableSubtraction[emparams.Mod1e512]{}
	res := new(big.Int).Sub(modulus, big.NewInt(10))
	assignment := &variableSubtraction[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		A:        ValueOf[emparams.Mod1e512](10),
		B:        ValueOf[emparams.Mod1e512](20),
		Expected: ValueOf[emparams.Mod1e512](res),
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
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModMul(&c.A, &c.B, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableMultiplication(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	a, _ := rand.Int(rand.Reader, modulus)
	b, _ := rand.Int(rand.Reader, modulus)
	exp := new(big.Int).Mul(a, b)
	exp.Mod(exp, modulus)
	circuit := &variableMultiplication[emparams.Mod1e512]{}
	assignment := &variableMultiplication[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		A:        ValueOf[emparams.Mod1e512](a),
		B:        ValueOf[emparams.Mod1e512](b),
		Expected: ValueOf[emparams.Mod1e512](exp),
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
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.ModExp(&c.Base, &c.Exp, &c.Modulus)
	f.ModAssertIsEqual(&c.Expected, res, &c.Modulus)
	return nil
}

func TestVariableExp(t *testing.T) {
	assert := test.NewAssert(t)
	modulus, _ := new(big.Int).SetString("4294967311", 10)
	base, _ := rand.Int(rand.Reader, modulus)
	exp, _ := rand.Int(rand.Reader, modulus)
	expected := new(big.Int).Exp(base, exp, modulus)
	circuit := &variableExp[emparams.Mod1e512]{}
	assignment := &variableExp[emparams.Mod1e512]{
		Modulus:  ValueOf[emparams.Mod1e512](modulus),
		Base:     ValueOf[emparams.Mod1e512](base),
		Exp:      ValueOf[emparams.Mod1e512](exp),
		Expected: ValueOf[emparams.Mod1e512](expected),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}
