package emulated

import (
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type WrapperCircuit struct {
	X1, X2, X3, X4, X5, X6 frontend.Variable
	Res                    frontend.Variable
}

func (c *WrapperCircuit) Define(api frontend.API) error {
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := api.Mul(c.X1, c.X1, c.X1)
	fx2 := api.Mul(5, c.X2)
	nom := api.Sub(c.X3, c.X4)
	denom := api.Add(c.X5, c.X6)
	free := api.Div(nom, denom)
	res := api.Add(x13, fx2, free)
	api.AssertIsEqual(res, c.Res)
	return nil
}

type ConstantCircuit struct {
}

func (c *ConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	{
		c1 := ValueOf[Secp256k1Fp](42)
		b1, ok := f.constantValue(&c1)
		if !ok {
			return errors.New("42 should be constant")
		}
		if !(b1.IsUint64() && b1.Uint64() == 42) {
			return errors.New("42 != constant(42)")
		}
	}
	{
		m := f.Modulus()
		b1, ok := f.constantValue(m)
		if !ok {
			return errors.New("modulus should be constant")
		}
		if b1.Cmp(Secp256k1Fp{}.Modulus()) != 0 {
			return errors.New("modulus != constant(modulus)")
		}
	}

	return nil
}

func TestConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness ConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type MulConstantCircuit struct {
}

func (c *MulConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	c0 := ValueOf[Secp256k1Fp](0)
	c1 := ValueOf[Secp256k1Fp](0)
	c2 := ValueOf[Secp256k1Fp](0)
	r := f.Mul(&c0, &c1)
	f.AssertIsEqual(r, &c2)

	return nil
}

func TestMulConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness MulConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type SubConstantCircuit struct {
}

func (c *SubConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	c0 := ValueOf[Secp256k1Fp](0)
	c1 := ValueOf[Secp256k1Fp](0)
	c2 := ValueOf[Secp256k1Fp](0)
	r := f.Sub(&c0, &c1)
	if r.overflow != 0 {
		return fmt.Errorf("overflow %d != 0", r.overflow)
	}
	f.AssertIsEqual(r, &c2)

	return nil
}

func TestSubConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness SubConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}
