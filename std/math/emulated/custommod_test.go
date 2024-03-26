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
	res := v.Add(&c.A, &c.B, &c.Modulus)
	// v.f.AssertIsEqual(&c.Expected, res)
	// v.f.Println(res)
	_ = res
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
	res := v.Mul(&c.A, &c.B, &c.Modulus)
	// v.f.AssertIsEqual(&c.Expected, res)
	// v.f.Println(res)
	// v.f.Println(&c.Expected)
	_ = res
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
	assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BLS12_377))
}
