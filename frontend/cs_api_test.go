package frontend

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

func TestPrintln(t *testing.T) {
	// must not panic.
	cs := newConstraintSystem(ecc.BN254)
	one := cs.newPublicVariable()

	cs.Println(nil)
	cs.Println(1)
	cs.Println("a")
	cs.Println(new(big.Int).SetInt64(2))
	cs.Println(one)

	cs.Println(nil, 1, "a", new(big.Int), one)
}

// empty circuits
type IsBool1 struct{}
type IsBool2 struct{}
type IsBool3 struct{}

func TestIsBool1(t *testing.T) {

	var circuit IsBool1

	_, err := Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal("compilation failed", err)
	}
}

func TestIsBool2(t *testing.T) {

	var circuit IsBool2

	_, err := Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal("compilation failed", err)
	}
}

func TestIsBool3(t *testing.T) {

	var circuit IsBool3

	_, err := Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal("compilation failed", err)
	}
}

func (c *IsBool1) Define(curve ecc.ID, cs *ConstraintSystem) error {

	zero := cs.Constant(0)
	one := cs.Constant(1)
	cs.AssertIsBoolean(zero)
	cs.AssertIsBoolean(one)
	return nil
}

func (c *IsBool2) Define(curve ecc.ID, cs *ConstraintSystem) error {

	zero := cs.Constant(0)
	one := cs.Constant(1)
	sum := cs.Add(zero, one)
	cs.AssertIsBoolean(sum)
	return nil
}

func (c *IsBool3) Define(curve ecc.ID, cs *ConstraintSystem) error {

	zero := cs.Constant(0)
	one := cs.Constant(1)
	prod := cs.Mul(zero, one)
	cs.AssertIsBoolean(prod)

	return nil
}
