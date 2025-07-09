package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

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
