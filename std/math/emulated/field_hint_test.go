package emulated

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
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

func hintNativeInNativeOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		inputs, outputs := ctx.NativeInputsOutputs()
		if len(inputs) != 2 || len(outputs) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(inputs), len(outputs))
		}
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

type genericHintCircuitNativeInNativeOut[T FieldParams] struct {
	Nominator   frontend.Variable
	Denominator frontend.Variable
	Expected    frontend.Variable
}

func (c *genericHintCircuitNativeInNativeOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNative, outEm, err := f.NewHintGeneric(hintNativeInNativeOut, 1, 0, []frontend.Variable{c.Nominator, c.Denominator}, nil)
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNative) != 1 {
		return fmt.Errorf("expected 1 native output, got %d", len(outNative))
	}
	if len(outEm) != 0 {
		return fmt.Errorf("expected 0 emulated outputs, got %d", len(outEm))
	}
	api.AssertIsEqual(outNative[0], c.Expected)
	// duplicate constraint to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Expected, c.Expected)
	return nil
}

func testGenericHintNativeInNativeOut[T FieldParams](t *testing.T) {
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	b, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	c := new(big.Int).ModInverse(b, ecc.BN254.ScalarField())
	c.Mul(c, a)
	c.Mod(c, ecc.BN254.ScalarField())

	circuit := genericHintCircuitNativeInNativeOut[T]{}
	witness := genericHintCircuitNativeInNativeOut[T]{
		Nominator:   a,
		Denominator: b,
		Expected:    c,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

func TestGenericHintNativeInNativeOut(t *testing.T) {
	testGenericHintNativeInNativeOut[Goldilocks](t)
	testGenericHintNativeInNativeOut[Secp256k1Fp](t)
	testGenericHintNativeInNativeOut[BN254Fp](t)
}

func hintNativeInEmulatedOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		emulatedMod := moduli[0]
		nativeInputs, _ := ctx.NativeInputsOutputs()
		_, emulatedOut := ctx.InputsOutputs(emulatedMod)
		if len(nativeInputs) != 2 || len(emulatedOut) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(nativeInputs), len(emulatedOut))
		}
		nominator := nativeInputs[0]
		denominator := nativeInputs[1]
		res := new(big.Int).ModInverse(denominator, emulatedMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, emulatedMod)
		emulatedOut[0].Set(res)
		return nil
	})
}

type genericHintCircuitNativeInEmulatedOut[T FieldParams] struct {
	Nominator   frontend.Variable
	Denominator frontend.Variable
	Expected    Element[T]
}

func (c *genericHintCircuitNativeInEmulatedOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNative, outEm, err := f.NewHintGeneric(hintNativeInEmulatedOut, 0, 1, []frontend.Variable{c.Nominator, c.Denominator}, nil)
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNative) != 0 {
		return fmt.Errorf("expected 0 native outputs, got %d", len(outNative))
	}
	if len(outEm) != 1 {
		return fmt.Errorf("expected 1 emulated output, got %d", len(outEm))
	}
	f.AssertIsEqual(outEm[0], &c.Expected)
	return nil
}

func testGenericHintNativeInEmulatedOut[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	b, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := genericHintCircuitNativeInEmulatedOut[T]{}
	witness := genericHintCircuitNativeInEmulatedOut[T]{
		Nominator:   a,
		Denominator: b,
		Expected:    ValueOf[T](c),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

func TestGenericHintNativeInEmulatedOut(t *testing.T) {
	testGenericHintNativeInEmulatedOut[Goldilocks](t)
	testGenericHintNativeInEmulatedOut[Secp256k1Fp](t)
	testGenericHintNativeInEmulatedOut[BN254Fp](t)
}

func hintEmulatedInEmulatedOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		emulatedMod := moduli[0]
		emulatedIn, emulatedOut := ctx.InputsOutputs(emulatedMod)
		if len(emulatedIn) != 2 || len(emulatedOut) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(emulatedIn), len(emulatedOut))
		}
		nominator := emulatedIn[0]
		denominator := emulatedIn[1]
		res := new(big.Int).ModInverse(denominator, emulatedMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, emulatedMod)
		emulatedOut[0].Set(res)
		return nil
	})
}

type genericHintCircuitEmulatedInEmulatedOut[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    Element[T]
}

func (c *genericHintCircuitEmulatedInEmulatedOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNat, outEm, err := f.NewHintGeneric(hintEmulatedInEmulatedOut, 0, 1, nil, []*Element[T]{&c.Nominator, &c.Denominator})
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNat) != 0 {
		return fmt.Errorf("expected 0 native outputs, got %d", len(outNat))
	}
	if len(outEm) != 1 {
		return fmt.Errorf("expected 1 emulated output, got %d", len(outEm))
	}
	f.AssertIsEqual(outEm[0], &c.Expected)
	return nil
}

func testGenericHintEmulatedInEmulatedOut[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, fr.Modulus())
	c.Mul(c, a)
	c.Mod(c, fr.Modulus())

	circuit := genericHintCircuitEmulatedInEmulatedOut[T]{}
	witness := genericHintCircuitEmulatedInEmulatedOut[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    ValueOf[T](c),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
}

func TestGenericHintEmulatedInEmulatedOut(t *testing.T) {
	testGenericHintEmulatedInEmulatedOut[Goldilocks](t)
	testGenericHintEmulatedInEmulatedOut[Secp256k1Fp](t)
	testGenericHintEmulatedInEmulatedOut[BN254Fp](t)
}

func hintEmulatedInNativeOut(mod *big.Int, inputs, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		nativeMod, emulatedMod := ctx.NativeModulus(), moduli[0]
		_, nativeOut := ctx.NativeInputsOutputs()
		emulatedIn, _ := ctx.InputsOutputs(emulatedMod)
		if len(emulatedIn) != 2 || len(nativeOut) != 1 {
			return fmt.Errorf("expected 2 inputs and 1 output, got %d inputs and %d outputs", len(emulatedIn), len(nativeOut))
		}
		nominator := emulatedIn[0]
		denominator := emulatedIn[1]
		res := new(big.Int).ModInverse(denominator, nativeMod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, nativeMod)
		nativeOut[0].Set(res)
		return nil
	})
}

type genericHintCircuitEmulatedInNativeOut[T FieldParams] struct {
	Nominator   Element[T]
	Denominator Element[T]
	Expected    frontend.Variable
}

func (c *genericHintCircuitEmulatedInNativeOut[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNat, outEm, err := f.NewHintGeneric(hintEmulatedInNativeOut, 1, 0, nil, []*Element[T]{&c.Nominator, &c.Denominator})
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNat) != 1 {
		return fmt.Errorf("expected 1 native output, got %d", len(outNat))
	}
	if len(outEm) != 0 {
		return fmt.Errorf("expected 0 emulated outputs, got %d", len(outEm))
	}
	api.AssertIsEqual(outNat[0], c.Expected)
	// duplicate constraint to ensure PLONK circuit has at least two constraints
	api.AssertIsEqual(c.Expected, c.Expected)
	return nil
}

func testGenericHintEmulatedInNativeOut[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c := new(big.Int).ModInverse(b, ecc.BN254.ScalarField())
	c.Mul(c, a)
	c.Mod(c, ecc.BN254.ScalarField())
	circuit := genericHintCircuitEmulatedInNativeOut[T]{}
	witness := genericHintCircuitEmulatedInNativeOut[T]{
		Nominator:   ValueOf[T](a),
		Denominator: ValueOf[T](b),
		Expected:    c,
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

func TestGenericHintEmulatedInNativeOut(t *testing.T) {
	testGenericHintEmulatedInNativeOut[Goldilocks](t)
	testGenericHintEmulatedInNativeOut[Secp256k1Fp](t)
	testGenericHintEmulatedInNativeOut[BN254Fp](t)
}

func crossfieldHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return UnwrapHintContext(nativeMod, nativeInputs, nativeOutputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("expected 2 moduli, got %d", len(moduli))
		}
		emulatedMod1, emulatedMod2 := moduli[0], moduli[1]
		nativeInputs, nativeOutputs := ctx.NativeInputsOutputs()
		emulatedInputs1, emulatedOutputs1 := ctx.InputsOutputs(emulatedMod1)
		emulatedInputs2, emulatedOutputs2 := ctx.InputsOutputs(emulatedMod2)
		if len(nativeInputs) != 2 || len(nativeOutputs) != 1 ||
			len(emulatedInputs1) != 2 || len(emulatedOutputs1) != 1 ||
			len(emulatedInputs2) != 2 || len(emulatedOutputs2) != 1 {
			return errors.New("unexpected number of inputs or outputs")
		}
		res := new(big.Int)
		res.Mul(res, nativeInputs[0])
		res.Mul(res, nativeInputs[1])
		res.Mod(res, emulatedInputs1[0])
		res.Mul(res, emulatedInputs1[1])
		res.Mul(res, emulatedInputs2[0])
		res.Mul(res, emulatedInputs2[1])
		nativeOutputs[0].Mod(res, nativeMod)
		emulatedOutputs1[0].Mod(res, emulatedMod1)
		emulatedOutputs2[0].Mod(res, emulatedMod2)
		return nil
	})
}

type crossfieldHintCircuit[T1, T2 FieldParams] struct {
	A, B              frontend.Variable
	C, D              Element[T1]
	E, F              Element[T2]
	ExpectedNative    frontend.Variable
	ExpectedEmulated1 Element[T1]
	ExpectedEmulated2 Element[T2]
}

func (c *crossfieldHintCircuit[T1, T2]) Define(api frontend.API) error {
	f1, err := NewField[T1](api)
	if err != nil {
		return fmt.Errorf("new field T1: %w", err)
	}
	f2, err := NewField[T2](api)
	if err != nil {
		return fmt.Errorf("new field T2: %w", err)
	}
	outNative, outEm1, outEm2, err := NewVarGenericHint(api,
		1, 1, 1,
		[]frontend.Variable{c.A, c.B},
		[]*Element[T1]{&c.C, &c.D},
		[]*Element[T2]{&c.E, &c.F},
		crossfieldHint)
	if err != nil {
		return fmt.Errorf("new cross field hint: %w", err)
	}
	api.AssertIsEqual(outNative[0], c.ExpectedNative)
	f1.AssertIsEqual(outEm1[0], &c.ExpectedEmulated1)
	f2.AssertIsEqual(outEm2[0], &c.ExpectedEmulated2)
	return nil
}

func testCrossFieldHint[T1, T2 FieldParams](t *testing.T) {
	var fr1 T1
	var fr2 T2
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	b, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	c, _ := rand.Int(rand.Reader, fr1.Modulus())
	d, _ := rand.Int(rand.Reader, fr1.Modulus())
	e, _ := rand.Int(rand.Reader, fr2.Modulus())
	f, _ := rand.Int(rand.Reader, fr2.Modulus())
	res := new(big.Int)
	res.Mul(res, a)
	res.Mul(res, b)
	res.Mod(res, c)
	res.Mul(res, d)
	res.Mul(res, e)
	res.Mul(res, f)
	res1 := new(big.Int).Mod(res, ecc.BN254.ScalarField())
	res2 := new(big.Int).Mod(res, fr1.Modulus())
	res3 := new(big.Int).Mod(res, fr2.Modulus())
	circuit := crossfieldHintCircuit[T1, T2]{}
	witness := crossfieldHintCircuit[T1, T2]{
		A:                 a,
		B:                 b,
		C:                 ValueOf[T1](c),
		D:                 ValueOf[T1](d),
		E:                 ValueOf[T2](e),
		F:                 ValueOf[T2](f),
		ExpectedNative:    res1,
		ExpectedEmulated1: ValueOf[T1](res2),
		ExpectedEmulated2: ValueOf[T2](res3),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

func TestCrossFieldHint(t *testing.T) {
	testCrossFieldHint[Goldilocks, Secp256k1Fp](t)
	testCrossFieldHint[Goldilocks, BN254Fp](t)
	testCrossFieldHint[Secp256k1Fp, Goldilocks](t)
	testCrossFieldHint[Secp256k1Fp, BN254Fp](t)
	testCrossFieldHint[BN254Fp, Goldilocks](t)
	testCrossFieldHint[BN254Fp, Secp256k1Fp](t)
}

func matchingFieldHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return UnwrapHintContext(mod, inputs, outputs, func(ctx HintContext) error {
		moduli := ctx.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("expected 1 moduli, got %d", len(moduli))
		}
		nativeMod, emulatedMod := ctx.NativeModulus(), moduli[0]
		nativeInputs, nativeOutputs := ctx.NativeInputsOutputs()
		emulatedInputs, emulatedOutputs := ctx.InputsOutputs(emulatedMod)
		if len(nativeInputs) != 2 || len(nativeOutputs) != 1 ||
			len(emulatedInputs) != 2 || len(emulatedOutputs) != 1 {
			return errors.New("unexpected number of inputs or outputs")
		}
		res1 := new(big.Int).Mul(nativeInputs[0], nativeInputs[1])
		res1.Mod(res1, nativeMod)
		res2 := new(big.Int).Mul(emulatedInputs[0], emulatedInputs[1])
		res2.Mod(res2, emulatedMod)
		nativeOutputs[0].Mod(res1, nativeMod)
		emulatedOutputs[0].Mod(res2, emulatedMod)
		return nil
	})
}

type matchingFieldHintCircuit[T FieldParams] struct {
	A, B             frontend.Variable
	C, D             Element[T]
	ExpectedNative   frontend.Variable
	ExpectedEmulated Element[T]
}

func (c *matchingFieldHintCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	outNative, outEm, err := f.NewHintGeneric(matchingFieldHint, 1, 1, []frontend.Variable{c.A, c.B}, []*Element[T]{&c.C, &c.D})
	if err != nil {
		return fmt.Errorf("new hint: %w", err)
	}
	if len(outNative) != 1 {
		return fmt.Errorf("expected 1 native output, got %d", len(outNative))
	}
	if len(outEm) != 1 {
		return fmt.Errorf("expected 1 emulated output, got %d", len(outEm))
	}
	api.AssertIsEqual(outNative[0], c.ExpectedNative)
	f.AssertIsEqual(outEm[0], &c.ExpectedEmulated)
	return nil
}

func testMatchingFieldHint[T FieldParams](t *testing.T) {
	var fr T
	assert := test.NewAssert(t)
	a, _ := rand.Int(rand.Reader, fr.Modulus())
	b, _ := rand.Int(rand.Reader, fr.Modulus())
	c, _ := rand.Int(rand.Reader, fr.Modulus())
	d, _ := rand.Int(rand.Reader, fr.Modulus())
	res1 := new(big.Int).Mod(new(big.Int).Mul(a, b), fr.Modulus())
	res2 := new(big.Int).Mod(new(big.Int).Mul(c, d), fr.Modulus())

	circuit := matchingFieldHintCircuit[T]{}
	witness := matchingFieldHintCircuit[T]{
		A:                a,
		B:                b,
		C:                ValueOf[T](c),
		D:                ValueOf[T](d),
		ExpectedNative:   res1,
		ExpectedEmulated: ValueOf[T](res2),
	}
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(utils.FieldToCurve(fr.Modulus())))
}

func TestMatchingFieldHint(t *testing.T) {
	testMatchingFieldHint[BN254Fr](t)
	testMatchingFieldHint[BLS12381Fr](t)
}
