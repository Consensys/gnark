// Package uints implements optimised byte and long integer operations.
//
// Usually arithmetic in a circuit is performed in the native field, which is of
// prime order. However, for compatibility with native operations we rely on
// operating on smaller primitive types as 8-bit, 32-bit and 64-bit integer.
// Naively, these operations have to be implemented bitwise as there are no
// closed equations for boolean operations (XOR, AND, OR).
//
// However, the bitwise approach is very inefficient and leads to several
// constraints per bit. Accumulating over a long integer, it leads to very
// inefficients circuits.
//
// This package performs boolean operations using lookup tables on bytes. So,
// long integers are split into 4 or 8 bytes and we perform the operations
// bytewise. In the lookup tables, we store results for all possible 2^8×2^8
// inputs. With this approach, every bytewise operation costs as single lookup,
// which depending on the backend is relatively cheap (one to three
// constraints).
//
// NB! The package is still work in progress. The interfaces and implementation
// details most certainly changes over time. We cannot ensure the soundness of
// the operations.
package uints

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/logderivprecomp"
	"github.com/consensys/gnark/std/math/bitslice"
)

// TODO: all operations can take rand linear combinations instead. Then instead
// of one check can perform multiple at the same time.

// TODO: maybe can store everything in a single table? Later! Or if we have a
// lot of queries then makes sense to extract into separate table?

// TODO: add helper method to call hints which allows to pass in uint8s (bytes)
// and returns bytes. Then can to byte array manipulation nicely. It is useful
// for X509. For the implementation we want to pack as much bytes into a field
// element as possible.

type U64 [8]U8
type U32 [4]U8

type Long interface{ U32 | U64 }

type BinaryField[T Long] struct {
	*Bytes
}

// NewBinaryField creates a new [BinaryField] for the given integer type T
// specified by parameter [Long]. It allows to manipulate long integers in
// circuit.
func NewBinaryField[T Long](api frontend.API) (*BinaryField[T], error) {
	bts, err := NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("new bytes: %w", err)
	}
	return &BinaryField[T]{Bytes: bts}, nil
}

// New is an alias to [NewBinaryField]. It is retained for backwards
// compatibility. New uses should use [NewBinaryField] instead.
func New[T Long](api frontend.API) (*BinaryField[T], error) {
	return NewBinaryField[T](api)
}

// NewU32 creates a new [U32] value. It represents a 32-bit unsigned integer
// which is split into 4 bytes. It can both be used in-circuit to initialize a
// constant or as a witness assignment. For in-circuit initialization use
// [BinaryField.ValueOf] method instead which ensures that the value is range
// checked.
func NewU32(v uint32) U32 {
	return [4]U8{
		NewU8(uint8((v >> (0 * 8)) & 0xff)),
		NewU8(uint8((v >> (1 * 8)) & 0xff)),
		NewU8(uint8((v >> (2 * 8)) & 0xff)),
		NewU8(uint8((v >> (3 * 8)) & 0xff)),
	}
}

// NewU64 creates a new [U64] value. It represents a 64-bit unsigned integer
// which is split into 4 bytes. It can both be used in-circuit to initialize a
// constant or as a witness assignment. For in-circuit initialization use
// [BinaryField.ValueOf] method instead which ensures that the value is range
// checked.
func NewU64(v uint64) U64 {
	return [8]U8{
		NewU8(uint8((v >> (0 * 8)) & 0xff)),
		NewU8(uint8((v >> (1 * 8)) & 0xff)),
		NewU8(uint8((v >> (2 * 8)) & 0xff)),
		NewU8(uint8((v >> (3 * 8)) & 0xff)),
		NewU8(uint8((v >> (4 * 8)) & 0xff)),
		NewU8(uint8((v >> (5 * 8)) & 0xff)),
		NewU8(uint8((v >> (6 * 8)) & 0xff)),
		NewU8(uint8((v >> (7 * 8)) & 0xff)),
	}
}

// NewU8Array is a utility method to create a slice of [U8] from a slice of
// uint8.
func NewU8Array(v []uint8) []U8 {
	ret := make([]U8, len(v))
	for i := range v {
		ret[i] = NewU8(v[i])
	}
	return ret
}

// NewU32Array is a utility method to create a slice of [U32] from a slice of
// uint32.
func NewU32Array(v []uint32) []U32 {
	ret := make([]U32, len(v))
	for i := range v {
		ret[i] = NewU32(v[i])
	}
	return ret
}

// NewU64Array is a utility method to create a slice of [U64] from a slice of
// uint64.
func NewU64Array(v []uint64) []U64 {
	ret := make([]U64, len(v))
	for i := range v {
		ret[i] = NewU64(v[i])
	}
	return ret
}

func (bf *BinaryField[T]) ByteValueOf(a frontend.Variable) U8 {
	return bf.Bytes.ValueOf(a)
}

func (bf *BinaryField[T]) ValueOf(a frontend.Variable) T {
	var r T
	bts, err := bf.api.Compiler().NewHint(toBytes, bf.lenBts(), bf.lenBts(), a)
	if err != nil {
		panic(err)
	}

	for i := range bts {
		r[i] = bf.Bytes.ValueOf(bts[i])
	}
	expectedValue := bf.ToValue(r)
	bf.api.AssertIsEqual(a, expectedValue)

	return r
}

func (bf *BinaryField[T]) ToValue(a T) frontend.Variable {
	v := make([]frontend.Variable, bf.lenBts())
	for i := range v {
		v[i] = bf.api.Mul(bf.Value(a[i]), 1<<(i*8))
	}
	vv := bf.api.Add(v[0], v[1], v[2:]...)
	return vv
}

func (bf *BinaryField[T]) PackMSB(a ...U8) T {
	var ret T
	for i := range a {
		ret[len(a)-i-1] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) PackLSB(a ...U8) T {
	var ret T
	for i := range a {
		ret[i] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) UnpackMSB(a T) []U8 {
	ret := make([]U8, bf.lenBts())
	for i := range ret {
		ret[bf.lenBts()-i-1] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) UnpackLSB(a T) []U8 {
	// cannot deduce that a can be cast to []U8
	ret := make([]U8, bf.lenBts())
	for i := range ret {
		ret[i] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) twoArgWideFn(tbl *logderivprecomp.Precomputed, a ...T) T {
	var r T
	for i, v := range bf.reslice(a) {
		r[i] = bf.twoArgFn(tbl, v...)
	}
	return r
}

func (bf *BinaryField[T]) And(a ...T) T { return bf.twoArgWideFn(bf.andT, a...) }
func (bf *BinaryField[T]) Xor(a ...T) T { return bf.twoArgWideFn(bf.xorT, a...) }
func (bf *BinaryField[T]) Or(a ...T) T  { return bf.twoArgWideFn(bf.orT, a...) }

func (bf *BinaryField[T]) Not(a T) T {
	var r T
	for i := 0; i < bf.lenBts(); i++ {
		r[i] = bf.Bytes.Not(a[i])
	}
	return r
}

func (bf *BinaryField[T]) Add(a ...T) T {
	tLen := bf.lenBts() * 8
	inLen := len(a)
	va := make([]frontend.Variable, inLen)
	for i := range a {
		va[i] = bf.ToValue(a[i])
	}
	vres := bf.api.Add(va[0], va[1], va[2:]...)
	maxBitlen := bits.Len(uint(inLen)) + tLen
	// bitslice.Partition below checks that the input is less than 2^maxBitlen and that we have omitted carry correctly
	vreslow, _ := bitslice.Partition(bf.api, vres, uint(tLen), bitslice.WithNbDigits(maxBitlen), bitslice.WithUnconstrainedOutputs())
	res := bf.ValueOf(vreslow)
	return res
}

func (bf *BinaryField[T]) Lrot(a T, c int) T {
	l := bf.lenBts()
	if c < 0 {
		c = l*8 + c
	}
	shiftBl := c / 8
	shiftBt := c % 8
	revShiftBt := 8 - shiftBt
	if revShiftBt == 8 {
		revShiftBt = 0
	}
	partitioned := make([][2]frontend.Variable, l)
	for i := range partitioned {
		lower, upper := bitslice.Partition(bf.api, bf.Value(a[i]), uint(revShiftBt), bitslice.WithNbDigits(8))
		// here lower and upper are already range checked
		partitioned[i] = [2]frontend.Variable{lower, upper}
	}
	var ret T
	for i := 0; i < l; i++ {
		if shiftBt != 0 {
			ret[(i+shiftBl)%l] = bf.packInternal(bf.api.Add(bf.api.Mul(1<<(shiftBt), partitioned[i][0]), partitioned[(i+l-1)%l][1]))
		} else {
			ret[(i+shiftBl)%l] = bf.packInternal(partitioned[i][1])
		}
	}
	return ret
}

func (bf *BinaryField[T]) Rshift(a T, c int) T {
	lenB := bf.lenBts()
	shiftBl := c / 8
	shiftBt := c % 8
	partitioned := make([][2]frontend.Variable, lenB-shiftBl)
	for i := range partitioned {
		lower, upper := bitslice.Partition(bf.api, bf.Value(a[i+shiftBl]), uint(shiftBt), bitslice.WithNbDigits(8))
		// here lower and upper are already range checked
		partitioned[i] = [2]frontend.Variable{lower, upper}
	}
	var ret T
	for i := 0; i < bf.lenBts()-shiftBl-1; i++ {
		if shiftBt != 0 {
			ret[i] = bf.packInternal(bf.api.Add(partitioned[i][1], bf.api.Mul(1<<(8-shiftBt), partitioned[i+1][0])))
		} else {
			ret[i] = bf.packInternal(partitioned[i][1])
		}
	}
	ret[lenB-shiftBl-1] = bf.packInternal(partitioned[lenB-shiftBl-1][1])
	for i := lenB - shiftBl; i < lenB; i++ {
		ret[i] = NewU8(0)
	}
	return ret
}

func (bf *BinaryField[T]) ByteAssertEq(a, b U8) {
	bf.Bytes.AssertIsEqual(a, b)
}

func (bf *BinaryField[T]) AssertEq(a, b T) {
	for i := 0; i < bf.lenBts(); i++ {
		bf.ByteAssertEq(a[i], b[i])
	}
}

func (bf *BinaryField[T]) lenBts() int {
	var a T
	return len(a)
}

func (bf *BinaryField[T]) reslice(in []T) [][]U8 {
	if len(in) == 0 {
		panic("zero-length input")
	}
	ret := make([][]U8, bf.lenBts())
	for i := range ret {
		ret[i] = make([]U8, len(in))
	}
	for i := range in {
		for j := range bf.lenBts() {
			ret[j][i] = in[i][j]
		}
	}
	return ret
}
