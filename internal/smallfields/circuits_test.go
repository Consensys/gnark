package smallfields_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type NativeCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",secret"`
}

func (circuit *NativeCircuit) Define(api frontend.API) error {
	res := api.Mul(circuit.A, circuit.A)
	api.AssertIsEqual(res, circuit.B)
	return nil
}

type EmulatedCircuit[T emulated.FieldParams] struct {
	A emulated.Element[T] `gnark:",public"`
	B emulated.Element[T] `gnark:",secret"`
}

func (circuit *EmulatedCircuit[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&circuit.A, &circuit.A)
	f.AssertIsEqual(res, &circuit.B)
	return nil
}

func TestNativeCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	err := test.IsSolved(&NativeCircuit{}, &NativeCircuit{A: 2, B: 4}, goldilocks.Modulus())
	assert.NoError(err)
}

type smallBN struct {
	emparams.BN254Fp
}

func (smallBN) BitsPerLimb() uint {
	return 16
}

func (smallBN) NbLimbs() uint {
	return 16
}

func TestEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	err := test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](2), B: emulated.ValueOf[emparams.BN254Fp](4)}, goldilocks.Modulus())
	assert.Error(err)

	err = test.IsSolved(&EmulatedCircuit[smallBN]{}, &EmulatedCircuit[smallBN]{A: emulated.ValueOf[smallBN](2), B: emulated.ValueOf[smallBN](4)}, goldilocks.Modulus())
	assert.NoError(err)
}
