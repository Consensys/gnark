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

type valueOfCircuit[T Long] struct {
	In       frontend.Variable
	Expected T
}

func (c *valueOfCircuit[T]) Define(api frontend.API) error {
	uapi, err := New[T](api)
	if err != nil {
		return err
	}
	res := uapi.ValueOf(c.In)
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestValueOf(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	err = test.IsSolved(&valueOfCircuit[U64]{}, &valueOfCircuit[U64]{In: 0x12345678, Expected: [8]U8{NewU8(0x78), NewU8(0x56), NewU8(0x34), NewU8(0x12), NewU8(0), NewU8(0), NewU8(0), NewU8(0)}}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&valueOfCircuit[U32]{}, &valueOfCircuit[U32]{In: 0x12345678, Expected: [4]U8{NewU8(0x78), NewU8(0x56), NewU8(0x34), NewU8(0x12)}}, ecc.BN254.ScalarField())
	assert.NoError(err)
	err = test.IsSolved(&valueOfCircuit[U32]{}, &valueOfCircuit[U32]{In: 0x1234567812345678, Expected: [4]U8{NewU8(0x78), NewU8(0x56), NewU8(0x34), NewU8(0x12)}}, ecc.BN254.ScalarField())
	assert.Error(err)
}

type addCircuit struct {
	In       [2]U32
	Expected U32
}

func (c *addCircuit) Define(api frontend.API) error {
	uapi, err := New[U32](api)
	if err != nil {
		return err
	}
	res := uapi.Add(c.In[0], c.In[1])
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestAdd(t *testing.T) {
	assert := test.NewAssert(t)
	err := test.IsSolved(&addCircuit{}, &addCircuit{In: [2]U32{NewU32(^uint32(0)), NewU32(2)}, Expected: NewU32(1)}, ecc.BN254.ScalarField())
	assert.NoError(err)
}
