package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type VariableModulus[T FieldParams] struct {
	f *Field[T]
}

func NewVariableModulus[T FieldParams](api frontend.API) (*VariableModulus[T], error) {
	f, err := NewField[T](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	return &VariableModulus[T]{f: f}, nil
}

func (v *VariableModulus[T]) Mul(a, b *Element[T], modulus *Element[T]) *Element[T] {
	res := v.f.mulModCustom(a, b, 0, modulus)
	return res
}

func (v *VariableModulus[T]) Add(a, b *Element[T], modulus *Element[T]) *Element[T] {
	res := v.f.Add(a, b)
	return res
}

func (v *VariableModulus[T]) Sub(a, b *Element[T], modulus *Element[T]) {
	panic("todo")
	// like fixed modulus subtraction, but for sub padding need to use hint
	// instead of assuming T as a constant. And when doing as a hint, then need
	// to assert that the lower limbs are all ones at right places and the
	// highest limb covers everything else.
}

func (v *VariableModulus[T]) AssertIsEqual(a, b *Element[T]) {
	// like fixed modulus AssertIsEqual, but uses current Sub implementation for
	// computing the diff
	v.f.AssertIsEqual(a, b)
}

func (v *VariableModulus[T]) Exp(base, exp, modulus *Element[T]) *Element[T] {
	// does square-and-multiply with modulus reduction
	panic("todo")
}

type Any4096Field struct{}

func (Any4096Field) NbLimbs() uint     { return 64 }
func (Any4096Field) BitsPerLimb() uint { return 64 }
func (Any4096Field) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}

// TODO: how to we ensure that it is prime?
func (Any4096Field) IsPrime() bool { return false }
