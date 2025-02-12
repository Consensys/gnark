package emulated

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
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

func nnaHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHint(nativeInputs, nativeOutputs, func(mod *big.Int, inputs, outputs []*big.Int) error {
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, mod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, mod)
		outputs[0].Set(res)
		return nil
	})
}

type hintCircuit[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    Element[T]
}

func (c *hintCircuit[T]) Define(api frontend.API) error {
	field, err := NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHint(nnaHint, 1, &c.Nominator, &c.Denominator)
	if err != nil {
		return err
	}
	field.AssertIsEqual(res[0], &c.Expected)
	return nil
}

func testHint[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := hintCircuit[T]{}
	witness := hintCircuit[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    ValueOf[T](c),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithSolverOpts(solver.WithHints(nnaHint)))
}

func TestHint(t *testing.T) {
	testHint[Goldilocks](t)
	testHint[Secp256k1Fp](t)
	testHint[BN254Fp](t)
}

func nativeInputHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(nonnativeMod *big.Int, inputs, outputs []*big.Int) error {
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, nonnativeMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, nonnativeMod)
		outputs[0].Set(res)
		return nil
	})
}

type hintNativeInputCircuit[T FieldParams] struct {
	Nominator   frontend.Variable
	Denominator frontend.Variable
	Expected    Element[T]
}

func (c *hintNativeInputCircuit[T]) Define(api frontend.API) error {
	field, err := NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHintWithNativeInput(nativeInputHint, 1, c.Nominator, c.Denominator)
	if err != nil {
		return err
	}
	field.AssertIsEqual(res[0], &c.Expected)
	return nil
}

func testHintNativeInput[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, testCurve.ScalarField())
	b, _ := rand.Int(rand.Reader, testCurve.ScalarField())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := hintNativeInputCircuit[T]{}
	witness := hintNativeInputCircuit[T]{
		Nominator:   a,
		Denominator: b,
		Expected:    ValueOf[T](c),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(testCurve), test.WithSolverOpts(solver.WithHints(nativeInputHint)))
}

func TestHintNativeInput(t *testing.T) {
	testHintNativeInput[Goldilocks](t)
	testHintNativeInput[Secp256k1Fp](t)
	testHintNativeInput[BN254Fp](t)
}

func nativeOutputHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHintWithNativeOutput(nativeInputs, nativeOutputs, func(nonnativeMod *big.Int, inputs, outputs []*big.Int) error {
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, nativeMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, nativeMod)
		outputs[0].Set(res)
		return nil
	})
}

type hintNativeOutputCircuit[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    frontend.Variable
}

func (c *hintNativeOutputCircuit[T]) Define(api frontend.API) error {
	field, err := NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHintWithNativeOutput(nativeOutputHint, 1, &c.Nominator, &c.Denominator)
	if err != nil {
		return err
	}
	api.AssertIsEqual(res[0], c.Expected)
	api.AssertIsDifferent(c.Expected, 0)
	return nil
}

func testHintNativeOutput[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, testCurve.ScalarField())
	c.Mul(c, a)
	c.Mod(c, testCurve.ScalarField())

	circuit := hintNativeOutputCircuit[T]{}
	witness := hintNativeOutputCircuit[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    c,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(testCurve), test.WithSolverOpts(solver.WithHints(nativeOutputHint)))
}

func TestHintNativeOutput(t *testing.T) {
	testHintNativeOutput[Goldilocks](t)
	testHintNativeOutput[Secp256k1Fp](t)
	testHintNativeOutput[BN254Fp](t)
}
