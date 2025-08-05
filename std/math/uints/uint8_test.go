package uints

import (
	"fmt"
	"math/bits"
	"testing"

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
	assert.CheckCircuit(&lrotCirc{Shift: 4}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: 4, Out: NewU32(bits.RotateLeft32(0x12345678, 4))}))
	assert.CheckCircuit(&lrotCirc{Shift: 14}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: 14, Out: NewU32(bits.RotateLeft32(0x12345678, 14))}))
	assert.CheckCircuit(&lrotCirc{Shift: 3}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: 3, Out: NewU32(bits.RotateLeft32(0x12345678, 3))}))
	assert.CheckCircuit(&lrotCirc{Shift: 11}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: 11, Out: NewU32(bits.RotateLeft32(0x12345678, 11))}))
	// full block
	assert.CheckCircuit(&lrotCirc{Shift: 16}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: 16, Out: NewU32(bits.RotateLeft32(0x12345678, 16))}))
	// negative rotations
	assert.CheckCircuit(&lrotCirc{Shift: -4}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: -4, Out: NewU32(bits.RotateLeft32(0x12345678, -4))}))
	assert.CheckCircuit(&lrotCirc{Shift: -14}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: -14, Out: NewU32(bits.RotateLeft32(0x12345678, -14))}))
	assert.CheckCircuit(&lrotCirc{Shift: -3}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: -3, Out: NewU32(bits.RotateLeft32(0x12345678, -3))}))
	assert.CheckCircuit(&lrotCirc{Shift: -11}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: -11, Out: NewU32(bits.RotateLeft32(0x12345678, -11))}))
	assert.CheckCircuit(&lrotCirc{Shift: -16}, test.WithValidAssignment(&lrotCirc{In: NewU32(0x12345678), Shift: -16, Out: NewU32(bits.RotateLeft32(0x12345678, -16))}))
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
	assert.CheckCircuit(&rshiftCircuit{Shift: 4}, test.WithValidAssignment(&rshiftCircuit{Shift: 4, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 4)}))
	assert.CheckCircuit(&rshiftCircuit{Shift: 12}, test.WithValidAssignment(&rshiftCircuit{Shift: 12, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 12)}))
	assert.CheckCircuit(&rshiftCircuit{Shift: 3}, test.WithValidAssignment(&rshiftCircuit{Shift: 3, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 3)}))
	assert.CheckCircuit(&rshiftCircuit{Shift: 11}, test.WithValidAssignment(&rshiftCircuit{Shift: 11, In: NewU32(0x12345678), Expected: NewU32(0x12345678 >> 11)}))
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
	assert.CheckCircuit(&valueOfCircuit[U64]{}, test.WithValidAssignment(&valueOfCircuit[U64]{In: 0x12345678, Expected: [8]U8{NewU8(0x78), NewU8(0x56), NewU8(0x34), NewU8(0x12), NewU8(0), NewU8(0), NewU8(0), NewU8(0)}}))
	assert.CheckCircuit(&valueOfCircuit[U32]{}, test.WithValidAssignment(&valueOfCircuit[U32]{In: 0x12345678, Expected: [4]U8{NewU8(0x78), NewU8(0x56), NewU8(0x34), NewU8(0x12)}}))
	assert.CheckCircuit(&valueOfCircuit[U32]{}, test.WithInvalidAssignment(&valueOfCircuit[U32]{In: 0x1234567812345678, Expected: [4]U8{NewU8(0x78), NewU8(0x56), NewU8(0x34), NewU8(0x12)}}))
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
	assert.CheckCircuit(&addCircuit{}, test.WithValidAssignment(&addCircuit{In: [2]U32{NewU32(^uint32(0)), NewU32(2)}, Expected: NewU32(1)}))
}

// Add tests where we try to initialize unconstrained U8
type ConstrainedCheckCircuit struct {
	A, B, C U8
	mode    int
}

func (c *ConstrainedCheckCircuit) Define(api frontend.API) error {
	uapi, err := NewBytes(api)
	if err != nil {
		return fmt.Errorf("NewBytes: %w", err)
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
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 0}, test.WithValidAssignment(&ConstrainedCheckCircuit{A: NewU8(0x0f), B: NewU8(0xf0), C: NewU8(0x00)}))
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 0}, test.WithInvalidAssignment(&ConstrainedCheckCircuit{A: U8{Val: 0x00ff}, B: U8{Val: 0xf0f}, C: U8{Val: 0x00f}}))
	}, "and")
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 1}, test.WithValidAssignment(&ConstrainedCheckCircuit{A: NewU8(0x0f), B: NewU8(0xf0), C: NewU8(0xff)}))
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 1}, test.WithInvalidAssignment(&ConstrainedCheckCircuit{A: U8{Val: 0x0f00}, B: U8{Val: 0x0f0}, C: U8{Val: 0xff0}}))
	}, "or")
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 2}, test.WithValidAssignment(&ConstrainedCheckCircuit{A: NewU8(0x0f), B: NewU8(0xf0), C: NewU8(0xff)}))
		assert.CheckCircuit(&ConstrainedCheckCircuit{mode: 2}, test.WithInvalidAssignment(&ConstrainedCheckCircuit{A: U8{Val: 0x0f0f}, B: U8{Val: 0x0ff}, C: U8{Val: 0xff0}}))
	}, "xor")
}

type ToValueCircuit struct {
	In        U32
	withCheck bool
	Expected  frontend.Variable
}

func (c *ToValueCircuit) Define(api frontend.API) error {
	uapi, err := New[U32](api)
	if err != nil {
		return fmt.Errorf("New: %w", err)
	}
	res := uapi.ToValue(c.In)
	if c.withCheck {
		api.AssertIsEqual(res, c.Expected)
	}
	return nil
}

func TestToValue(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&ToValueCircuit{withCheck: true}, test.WithValidAssignment(&ToValueCircuit{In: NewU32(0x12345678), Expected: 0x12345678}))
	assert.CheckCircuit(&ToValueCircuit{withCheck: false}, test.WithInvalidAssignment(&ToValueCircuit{In: [4]U8{{Val: 0x780}, {Val: 0x56}, {Val: 0x34}, {Val: 0x12}}, Expected: 0x12345678}))
}

type ValueWitnessCircuit struct {
	In       U8
	Expected frontend.Variable
}

func (c *ValueWitnessCircuit) Define(api frontend.API) error {
	uapi, err := NewBytes(api)
	if err != nil {
		return fmt.Errorf("NewBytes: %w", err)
	}
	res := uapi.Value(c.In)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestValueWitness(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&ValueWitnessCircuit{}, test.WithValidAssignment(&ValueWitnessCircuit{In: NewU8(0x12), Expected: 0x12}))
	assert.CheckCircuit(&ValueWitnessCircuit{}, test.WithInvalidAssignment(&ValueWitnessCircuit{In: U8{Val: 0x1234}, Expected: 0x1234}))
}

type ValueInCircuitCircuit struct {
	In       frontend.Variable
	Expected frontend.Variable
}

func (c *ValueInCircuitCircuit) Define(api frontend.API) error {
	uapi, err := NewBytes(api)
	if err != nil {
		return fmt.Errorf("NewBytes: %w", err)
	}
	in := U8{Val: c.In}
	res := uapi.Value(in)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestValueInCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&ValueInCircuitCircuit{}, test.WithValidAssignment(&ValueInCircuitCircuit{In: 0x12, Expected: 0x12}))
	assert.CheckCircuit(&ValueInCircuitCircuit{}, test.WithInvalidAssignment(&ValueInCircuitCircuit{In: 0x1234, Expected: 0x1234}))
}
