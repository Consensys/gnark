package emulated

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"
)

func (f *Field[T]) ModMul(a, b *Element[T], modulus *Element[T]) *Element[T] {
	res := f.mulMod(a, b, 0, modulus)
	return res
}

func (f *Field[T]) ModAdd(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// inlined version of [Field.reduceAndOp] which uses variable-modulus reduction
	var nextOverflow uint
	var err error
	var target overflowError
	for nextOverflow, err = f.addPreCond(a, b); errors.As(err, &target); nextOverflow, err = f.addPreCond(a, b) {
		if errors.As(err, &target) {
			if !target.reduceRight {
				a = f.mulMod(a, f.shortOne(), 0, modulus)
			} else {
				b = f.mulMod(b, f.shortOne(), 0, modulus)
			}
		}
	}
	res := f.add(a, b, nextOverflow)
	return res
}

func (f *Field[T]) modSub(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// like fixed modulus subtraction, but for sub padding need to use hint
	// instead of assuming T as a constant. And when doing as a hint, then need
	// to assert that the padding is a multiple of the modulus (done inside callSubPaddingHint)
	nextOverflow := max(b.overflow+1, a.overflow) + 1
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	padding := f.callSubPaddingHint(b.overflow, uint(nbLimbs), modulus)
	for i := range limbs {
		limbs[i] = padding.Limbs[i]
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Sub(limbs[i], b.Limbs[i])
		}
	}
	res := f.newInternalElement(limbs, nextOverflow)
	return res
}

func (f *Field[T]) ModAssertIsEqual(a, b *Element[T], modulus *Element[T]) {
	// like fixed modulus AssertIsEqual, but uses current Sub implementation for
	// computing the diff
	diff := f.modSub(b, a, modulus)
	f.checkZero(diff, modulus)
}

func (f *Field[T]) ModExp(base, exp, modulus *Element[T]) *Element[T] {
	expBts := f.ToBits(exp)
	res := f.One()
	for i := range expBts {
		res = f.Select(expBts[i], f.ModMul(base, res, modulus), res)
		base = f.ModMul(base, base, modulus)
	}
	return res
}

func (f *Field[T]) callSubPaddingHint(overflow uint, nbLimbs uint, modulus *Element[T]) *Element[T] {
	var fp T
	inputs := []frontend.Variable{fp.NbLimbs(), fp.BitsPerLimb(), overflow, nbLimbs}
	inputs = append(inputs, modulus.Limbs...)
	res, err := f.api.NewHint(SubPaddingHint, int(nbLimbs), inputs...)
	if err != nil {
		panic(fmt.Sprintf("sub padding hint: %v", err))
	}
	for i := range res {
		f.checker.Check(res[i], int(fp.BitsPerLimb()+overflow+1))
	}
	padding := f.newInternalElement(res, fp.BitsPerLimb()+overflow+1)
	f.checkZero(padding, modulus)
	return padding
}
