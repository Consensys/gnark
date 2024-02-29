package uints

import (
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type lrotCirc struct {
	In    U32
	Out   U32
	Shift int
}

func (c *lrotCirc) Define(api frontend.API) error {
	uapi, err := New[U32](api)
	if err != nil {
		return err
	}
	res := uapi.Lrot(c.In, c.Shift)
	uapi.AssertEq(c.Out, res)
	return nil
}

func TestLeftRotation(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	err = test.IsSolved(&lrotCirc{Shift: 4}, &lrotCirc{In: NewU32(0x12345678), Shift: 4, Out: NewU32(bits.RotateLeft32(0x12345678, 4))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: 14}, &lrotCirc{In: NewU32(0x12345678), Shift: 14, Out: NewU32(bits.RotateLeft32(0x12345678, 14))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: 3}, &lrotCirc{In: NewU32(0x12345678), Shift: 3, Out: NewU32(bits.RotateLeft32(0x12345678, 3))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: 11}, &lrotCirc{In: NewU32(0x12345678), Shift: 11, Out: NewU32(bits.RotateLeft32(0x12345678, 11))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	// full block
	err = test.IsSolved(&lrotCirc{Shift: 16}, &lrotCirc{In: NewU32(0x12345678), Shift: 16, Out: NewU32(bits.RotateLeft32(0x12345678, 16))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	// negative rotations
	err = test.IsSolved(&lrotCirc{Shift: -4}, &lrotCirc{In: NewU32(0x12345678), Shift: -4, Out: NewU32(bits.RotateLeft32(0x12345678, -4))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: -14}, &lrotCirc{In: NewU32(0x12345678), Shift: -14, Out: NewU32(bits.RotateLeft32(0x12345678, -14))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: -3}, &lrotCirc{In: NewU32(0x12345678), Shift: -3, Out: NewU32(bits.RotateLeft32(0x12345678, -3))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: -11}, &lrotCirc{In: NewU32(0x12345678), Shift: -11, Out: NewU32(bits.RotateLeft32(0x12345678, -11))}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&lrotCirc{Shift: -16}, &lrotCirc{In: NewU32(0x12345678), Shift: -16, Out: NewU32(bits.RotateLeft32(0x12345678, -16))}, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type rshiftCircuit struct {
	In, Expected U32
	Shift        int
}

func (c *rshiftCircuit) Define(api frontend.API) error {
	uapi, err := New[U32](api)
	if err != nil {
		return err
	}
	res := uapi.Rshift(c.In, c.Shift)
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestRshift(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	err = test.IsSolved(&rshiftCircuit{Shift: 4}, &rshiftCircuit{Shift: 4, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 4)}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&rshiftCircuit{Shift: 12}, &rshiftCircuit{Shift: 12, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 12)}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&rshiftCircuit{Shift: 3}, &rshiftCircuit{Shift: 3, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 3)}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&rshiftCircuit{Shift: 11}, &rshiftCircuit{Shift: 11, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 11)}, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type byteArrayValueOfCircuit struct {
	In       frontend.Variable
	Expected []U8
}

func (c *byteArrayValueOfCircuit) Define(api frontend.API) error {
	uapi, err := New[U32](api)
	if err != nil {
		return err
	}

	res := uapi.ByteArrayValueOf(c.In, 3)
	api.AssertIsEqual(len(res), len(c.Expected))
	for i := 0; i < len(res); i++ {
		uapi.ByteAssertEq(res[i], c.Expected[i])
	}

	return nil
}

func TestByteArrayValueOf(t *testing.T) {
	assert := test.NewAssert(t)
	a, b, c := 13, 17, 19
	p := a + (b << 8) + (c << 16)
	expected := NewU8Array([]uint8{uint8(a), uint8(b), uint8(c)})
	circuit := &byteArrayValueOfCircuit{
		Expected: expected,
	}
	assignment := &byteArrayValueOfCircuit{
		In:       frontend.Variable(p),
		Expected: expected,
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
