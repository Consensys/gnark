package uints_test

import (
	"fmt"
	"math/bits"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type lrotCirc struct {
	In    uints.U32
	Out   uints.U32
	Shift int
}

func (c *lrotCirc) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	res := uapi.Lrot(c.In, c.Shift)
	uapi.AssertEq(c.Out, res)
	return nil
}

func TestLeftRotation(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&lrotCirc{Shift: 4}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: 4, Out: uints.NewU32(bits.RotateLeft32(0x12345678, 4))}))
	assert.CheckCircuit(&lrotCirc{Shift: 14}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: 14, Out: uints.NewU32(bits.RotateLeft32(0x12345678, 14))}))
	assert.CheckCircuit(&lrotCirc{Shift: 3}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: 3, Out: uints.NewU32(bits.RotateLeft32(0x12345678, 3))}))
	assert.CheckCircuit(&lrotCirc{Shift: 11}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: 11, Out: uints.NewU32(bits.RotateLeft32(0x12345678, 11))}))
	// full block
	assert.CheckCircuit(&lrotCirc{Shift: 16}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: 16, Out: uints.NewU32(bits.RotateLeft32(0x12345678, 16))}))
	// negative rotations
	assert.CheckCircuit(&lrotCirc{Shift: -4}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: -4, Out: uints.NewU32(bits.RotateLeft32(0x12345678, -4))}))
	assert.CheckCircuit(&lrotCirc{Shift: -14}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: -14, Out: uints.NewU32(bits.RotateLeft32(0x12345678, -14))}))
	assert.CheckCircuit(&lrotCirc{Shift: -3}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: -3, Out: uints.NewU32(bits.RotateLeft32(0x12345678, -3))}))
	assert.CheckCircuit(&lrotCirc{Shift: -11}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: -11, Out: uints.NewU32(bits.RotateLeft32(0x12345678, -11))}))
	assert.CheckCircuit(&lrotCirc{Shift: -16}, test.WithValidAssignment(&lrotCirc{In: uints.NewU32(0x12345678), Shift: -16, Out: uints.NewU32(bits.RotateLeft32(0x12345678, -16))}))
}

type rshiftCircuit struct {
	In, Expected uints.U32
	Shift        int
}

func (c *rshiftCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	res := uapi.Rshift(c.In, c.Shift)
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestRshift(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&rshiftCircuit{Shift: 4}, test.WithValidAssignment(&rshiftCircuit{Shift: 4, In: uints.NewU32(0x12345678), Expected: uints.NewU32(0x12345678 >> 4)}))
	assert.CheckCircuit(&rshiftCircuit{Shift: 12}, test.WithValidAssignment(&rshiftCircuit{Shift: 12, In: uints.NewU32(0x12345678), Expected: uints.NewU32(0x12345678 >> 12)}))
	assert.CheckCircuit(&rshiftCircuit{Shift: 3}, test.WithValidAssignment(&rshiftCircuit{Shift: 3, In: uints.NewU32(0x12345678), Expected: uints.NewU32(0x12345678 >> 3)}))
	assert.CheckCircuit(&rshiftCircuit{Shift: 11}, test.WithValidAssignment(&rshiftCircuit{Shift: 11, In: uints.NewU32(0x12345678), Expected: uints.NewU32(0x12345678 >> 11)}))
}

type valueOfCircuit[T uints.Long] struct {
	In       frontend.Variable
	Expected T
}

func (c *valueOfCircuit[T]) Define(api frontend.API) error {
	uapi, err := uints.New[T](api)
	if err != nil {
		return err
	}
	res := uapi.ValueOf(c.In)
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestValueOf(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&valueOfCircuit[uints.U64]{}, test.WithValidAssignment(&valueOfCircuit[uints.U64]{In: 0x12345678, Expected: [8]uints.U8{uints.NewU8(0x78), uints.NewU8(0x56), uints.NewU8(0x34), uints.NewU8(0x12), uints.NewU8(0), uints.NewU8(0), uints.NewU8(0), uints.NewU8(0)}}))
	assert.CheckCircuit(&valueOfCircuit[uints.U32]{}, test.WithValidAssignment(&valueOfCircuit[uints.U32]{In: 0x12345678, Expected: [4]uints.U8{uints.NewU8(0x78), uints.NewU8(0x56), uints.NewU8(0x34), uints.NewU8(0x12)}}))
	assert.CheckCircuit(&valueOfCircuit[uints.U32]{}, test.WithInvalidAssignment(&valueOfCircuit[uints.U32]{In: 0x1234567812345678, Expected: [4]uints.U8{uints.NewU8(0x78), uints.NewU8(0x56), uints.NewU8(0x34), uints.NewU8(0x12)}}))
}

type addCircuit struct {
	In       [2]uints.U32
	Expected uints.U32
}

func (c *addCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	res := uapi.Add(c.In[0], c.In[1])
	uapi.AssertEq(res, c.Expected)
	return nil
}

func TestAdd(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&addCircuit{}, test.WithValidAssignment(&addCircuit{In: [2]uints.U32{uints.NewU32(^uint32(0)), uints.NewU32(2)}, Expected: uints.NewU32(1)}))
}

// Add tests where we try to initialize unconstrained uints.U8
type ConstrainedCheckCircuit struct {
	A, B, C uints.U8
	mode    int
}

func (c *ConstrainedCheckCircuit) Define(api frontend.API) error {
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("uints.NewBytes: %w", err)
	}
	switch c.mode {
	case 0:
		res := uapi.And(c.A, c.B)
		uapi.AssertIsEqual(res, c.C)
	case 1:
		res := uapi.Or(c.A, c.B)
		uapi.AssertIsEqual(res, c.C)
	case 2:
		res := uapi.Xor(c.A, c.B)
		uapi.AssertIsEqual(res, c.C)
	}
	return nil
}

func TestConstrainedCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 0}, test.WithValidAssignment(&ConstrainedCheckCircuit{A: uints.NewU8(0x0f), B: uints.NewU8(0xf0), C: uints.NewU8(0x00)}))
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 0}, test.WithInvalidAssignment(&ConstrainedCheckCircuit{A: uints.U8{Val: 0x00ff}, B: uints.U8{Val: 0xf0f}, C: uints.U8{Val: 0x00f}}))
	}, "and")
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 1}, test.WithValidAssignment(&ConstrainedCheckCircuit{A: uints.NewU8(0x0f), B: uints.NewU8(0xf0), C: uints.NewU8(0xff)}))
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 1}, test.WithInvalidAssignment(&ConstrainedCheckCircuit{A: uints.U8{Val: 0x0f00}, B: uints.U8{Val: 0x0f0}, C: uints.U8{Val: 0xff0}}))
	}, "or")
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 2}, test.WithValidAssignment(&ConstrainedCheckCircuit{A: uints.NewU8(0x0f), B: uints.NewU8(0xf0), C: uints.NewU8(0xff)}))
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 2}, test.WithInvalidAssignment(&ConstrainedCheckCircuit{A: uints.U8{Val: 0x0f0f}, B: uints.U8{Val: 0x0ff}, C: uints.U8{Val: 0xff0}}))
	}, "xor")
}

type ToValueCircuit struct {
	In        uints.U32
	withCheck bool
	Expected  frontend.Variable
}

func (c *ToValueCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return fmt.Errorf("uints.New: %w", err)
	}
	res := uapi.ToValue(c.In)
	if c.withCheck {
		api.AssertIsEqual(res, c.Expected)
	}
	return nil
}

func TestToValue(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&ToValueCircuit{withCheck: true}, test.WithValidAssignment(&ToValueCircuit{In: uints.NewU32(0x12345678), Expected: 0x12345678}))
	assert.CheckCircuit(&ToValueCircuit{withCheck: false}, test.WithInvalidAssignment(&ToValueCircuit{In: [4]uints.U8{{Val: 0x780}, {Val: 0x56}, {Val: 0x34}, {Val: 0x12}}, Expected: 0x12345678}))
}

type ValueWitnessCircuit struct {
	In       uints.U8
	Expected frontend.Variable
}

func (c *ValueWitnessCircuit) Define(api frontend.API) error {
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("uints.NewBytes: %w", err)
	}
	res := uapi.Value(c.In)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestValueWitness(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&ValueWitnessCircuit{}, test.WithValidAssignment(&ValueWitnessCircuit{In: uints.NewU8(0x12), Expected: 0x12}))
	assert.CheckCircuit(&ValueWitnessCircuit{}, test.WithInvalidAssignment(&ValueWitnessCircuit{In: uints.U8{Val: 0x1234}, Expected: 0x1234}))
}

type ValueInCircuitCircuit struct {
	In       frontend.Variable
	Expected frontend.Variable
}

func (c *ValueInCircuitCircuit) Define(api frontend.API) error {
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("uints.NewBytes: %w", err)
	}
	in := uints.U8{Val: c.In}
	res := uapi.Value(in)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestValueInCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&ValueInCircuitCircuit{}, test.WithValidAssignment(&ValueInCircuitCircuit{In: 0x12, Expected: 0x12}))
	assert.CheckCircuit(&ValueInCircuitCircuit{}, test.WithInvalidAssignment(&ValueInCircuitCircuit{In: 0x1234, Expected: 0x1234}))
}
