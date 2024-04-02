package emulated

import (
	"errors"
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

func (v *VariableModulus[T]) ModMul(a, b *Element[T], modulus *Element[T]) *Element[T] {
	res := v.f.mulMod(a, b, 0, modulus)
	return res
}

func (v *VariableModulus[T]) ModAdd(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// inlined version of [Field.reduceAndOp] which uses variable-modulus reduction
	var nextOverflow uint
	var err error
	var target overflowError
	for nextOverflow, err = v.f.addPreCond(a, b); errors.As(err, &target); nextOverflow, err = v.f.addPreCond(a, b) {
		if errors.As(err, &target) {
			if !target.reduceRight {
				a = v.f.mulMod(a, v.f.shortOne(), 0, modulus)
			} else {
				b = v.f.mulMod(b, v.f.shortOne(), 0, modulus)
			}
		}
	}
	res := v.f.add(a, b, nextOverflow)
	return res
}

func (v *VariableModulus[T]) modSub(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// like fixed modulus subtraction, but for sub padding need to use hint
	// instead of assuming T as a constant. And when doing as a hint, then need
	// to assert that the padding is a multiple of the modulus (done inside callSubPaddingHint)
	nextOverflow := max(b.overflow+1, a.overflow) + 1
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	padding := v.callSubPaddingHint(b.overflow, uint(nbLimbs), modulus)
	for i := range limbs {
		limbs[i] = padding.Limbs[i]
		if i < len(a.Limbs) {
			limbs[i] = v.f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = v.f.api.Sub(limbs[i], b.Limbs[i])
		}
	}
	res := v.f.newInternalElement(limbs, nextOverflow)
	return res
}

func (v *VariableModulus[T]) ModAssertIsEqual(a, b *Element[T], modulus *Element[T]) {
	// like fixed modulus AssertIsEqual, but uses current Sub implementation for
	// computing the diff
	diff := v.modSub(b, a, modulus)
	v.f.checkZero(diff, modulus)
}

func (v *VariableModulus[T]) ModExp(base, exp, modulus *Element[T]) *Element[T] {
	expBts := v.f.ToBits(exp)
	res := v.f.One()
	for i := range expBts {
		res = v.f.Select(expBts[i], v.ModMul(base, res, modulus), res)
		base = v.ModMul(base, base, modulus)
	}
	return res
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

func (v *VariableModulus[T]) callSubPaddingHint(overflow uint, nbLimbs uint, modulus *Element[T]) *Element[T] {
	var fp T
	inputs := []frontend.Variable{fp.NbLimbs(), fp.BitsPerLimb(), overflow, nbLimbs}
	inputs = append(inputs, modulus.Limbs...)
	res, err := v.f.api.NewHint(SubPaddingHint, int(nbLimbs), inputs...)
	if err != nil {
		panic(fmt.Sprintf("sub padding hint: %v", err))
	}
	for i := range res {
		v.f.checker.Check(res[i], int(fp.BitsPerLimb()+overflow+1))
	}
	padding := v.f.newInternalElement(res, fp.BitsPerLimb()+overflow+1)
	v.f.checkZero(padding, modulus)
	return padding
}
