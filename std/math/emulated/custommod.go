package emulated

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// ModMul computes a*b mod modulus. Instead of taking modulus as a constant
// parametrized by T, it is passed as an argument. This allows to use a variable
// modulus in the circuit. Type parameter T should be sufficiently big to fit a,
// b and modulus. Recommended to use [emparams.Mod1e512] or
// [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
func (f *Field[T]) ModMul(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// fast path when either of the inputs is zero then result is always zero
	if len(a.Limbs) == 0 || len(b.Limbs) == 0 {
		return f.Zero()
	}
	res := f.mulMod(a, b, 0, modulus)
	return res
}

// ModAdd computes a+b mod modulus. Instead of taking modulus as a constant
// parametrized by T, it is passed as an argument. This allows to use a variable
// modulus in the circuit. Type parameter T should be sufficiently big to fit a,
// b and modulus. Recommended to use [emparams.Mod1e512] or
// [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
func (f *Field[T]) ModAdd(a, b *Element[T], modulus *Element[T]) *Element[T] {
	// inlined version of [Field.reduceAndOp] which uses variable-modulus reduction
	var nextOverflow uint
	var err error
	var target overflowError
	for nextOverflow, err = f.addPreCond(a, b); errors.As(err, &target); nextOverflow, err = f.addPreCond(a, b) {
		if errors.As(err, &target) {
			if !target.reduceRight {
				a = f.mulMod(a, f.One(), 0, modulus)
			} else {
				b = f.mulMod(b, f.One(), 0, modulus)
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
	if nextOverflow > f.maxOverflow() {
		// TODO: in general we should handle it more gracefully, but this method
		// is only used in ModAssertIsEqual which in turn is only used in tests,
		// then for now we avoid automatic overflow handling (like we have for fixed modulus case).
		// We only panic here so that the user would know to manually handle the overflow.
		panic("next overflow would overflow the native field")
	}
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	padding := f.computeSubPaddingHint(b.overflow, uint(nbLimbs), modulus)
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

// ModAssertIsEqual asserts equality of a and b mod modulus. Instead of taking
// modulus as a constant parametrized by T, it is passed as an argument. This
// allows to use a variable modulus in the circuit. Type parameter T should be
// sufficiently big to fit a, b and modulus. Recommended to use
// [emparams.Mod1e512] or [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
func (f *Field[T]) ModAssertIsEqual(a, b *Element[T], modulus *Element[T]) {
	// like fixed modulus AssertIsEqual, but uses current Sub implementation for
	// computing the diff
	diff := f.modSub(b, a, modulus)
	f.checkZero(diff, modulus)
}

// ModExp computes base^exp mod modulus. Instead of taking modulus as a constant
// parametrized by T, it is passed as an argument. This allows to use a variable
// modulus in the circuit. Type parameter T should be sufficiently big to fit
// base, exp and modulus. Recommended to use [emparams.Mod1e512] or
// [emparams.Mod1e4096].
//
// NB! circuit complexity depends on T rather on the actual length of the modulus.
func (f *Field[T]) ModExp(base, exp, modulus *Element[T]) *Element[T] {
	// fasth path when the base is zero then result is always zero
	if len(base.Limbs) == 0 {
		return f.Zero()
	}

	// first, we hint the sub-exponents e1, e2 s.t.:
	// 		exp1 + exp2 * exp = 0 mod modulus, and
	// 		exp1, exp2 <= sqrt(modulus).
	expHint, err := f.NewHint(HalfGCDHint, 2, exp, modulus)
	if err != nil {
		panic(fmt.Sprintf("half-GCD hint: %v", err))
	}
	exp1, exp2 := expHint[0], expHint[1]
	// TODO: check decomposition
	// TODO: check sign

	// next, we hint the result of the exponentiation:
	// 		result = base^{exp} mod modulus
	resHint, err := f.NewHint(ExpHint, 1, base, exp, modulus)
	if err != nil {
		panic(fmt.Sprintf("exponentiation hint: %v", err))
	}
	result := resHint[0]

	// now, the following two equalities are equivalent:
	// 		base^{exp} = res [modulus] <==> base^{exp1} * res^{exp2} = 1 [modulus]
	product := f.ModMul(base, result, modulus)

	exp1Bts := f.ToBits(exp1)
	exp2Bts := f.ToBits(exp2)
	var st T
	n := st.Modulus().BitLen()>>1 + 1

	accumulator := f.Lookup2(exp1Bts[n-1], exp2Bts[n-1], f.One(), base, result, product)
	for i := n - 2; i >= 0; i-- {
		accumulator = f.ModMul(accumulator, accumulator, modulus)
		accumulator = f.ModMul(
			accumulator,
			f.Lookup2(exp1Bts[i], exp2Bts[i], f.One(), base, result, product),
			modulus,
		)
	}

	f.AssertIsEqual(accumulator, f.One())

	return result
}
