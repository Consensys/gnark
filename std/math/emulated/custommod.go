package emulated

import (
	"errors"

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
//
// The implementation uses windowed exponentiation with window size 4, which
// reduces the number of multiplications compared to binary square-and-multiply.
func (f *Field[T]) ModExp(base, exp, modulus *Element[T]) *Element[T] {
	// fast path when the base is zero then result is always zero
	if len(base.Limbs) == 0 {
		return f.Zero()
	}

	const windowSize = 4
	const tableSize = 1 << windowSize // 16

	// Build precomputation table: table[i] = base^i for i in [0, 2^windowSize)
	table := make([]*Element[T], tableSize)
	table[0] = f.One()
	table[1] = base
	for i := 2; i < tableSize; i++ {
		table[i] = f.ModMul(table[i-1], base, modulus)
	}

	// Get exponent bits (LSB first)
	expBts := f.ToBits(exp)
	n := len(expBts)

	// Pad to multiple of windowSize
	padding := (windowSize - (n % windowSize)) % windowSize
	paddedLen := n + padding

	// Process windows from MSB to LSB
	// expBts is LSB-first, so expBts[n-1] is MSB
	numWindows := paddedLen / windowSize

	// Initialize result with table lookup for the MSB window
	// MSB window (window 0) covers bits [(numWindows-1)*windowSize, numWindows*windowSize-1]
	// in the padded representation. Bits at indices >= n are padding zeros.
	msbWindowBits := make([]frontend.Variable, windowSize)
	msbBaseIdx := (numWindows - 1) * windowSize
	for i := 0; i < windowSize; i++ {
		actualIdx := msbBaseIdx + i
		if actualIdx < n {
			msbWindowBits[i] = expBts[actualIdx]
		} else {
			msbWindowBits[i] = 0
		}
	}
	res := f.tableLookup(table, msbWindowBits)

	// Process remaining windows
	for w := 1; w < numWindows; w++ {
		// Square windowSize times
		for i := 0; i < windowSize; i++ {
			res = f.ModMul(res, res, modulus)
		}

		// Extract window bits for this window
		// Window w covers bits from position (numWindows-1-w)*windowSize to (numWindows-w)*windowSize - 1
		// In the original LSB-first array
		windowBits := make([]frontend.Variable, windowSize)
		baseIdx := (numWindows - 1 - w) * windowSize
		for i := 0; i < windowSize; i++ {
			windowBits[i] = expBts[baseIdx+i]
		}

		// Table lookup and multiply
		selected := f.tableLookup(table, windowBits)
		res = f.ModMul(res, selected, modulus)
	}

	return res
}

// tableLookup performs a selection to retrieve table[idx] where idx is the
// value represented by bits (LSB first). Uses Lookup2 for efficiency.
// Assumes len(table) == 16 and len(bits) == 4.
func (f *Field[T]) tableLookup(table []*Element[T], bits []frontend.Variable) *Element[T] {
	// For 4 bits selecting from 16 elements:
	// - bits[0], bits[1] select within groups of 4
	// - bits[2], bits[3] select which group

	// First level: use bits[0], bits[1] to reduce 16 -> 4
	level1 := make([]*Element[T], 4)
	for i := 0; i < 4; i++ {
		level1[i] = f.Lookup2(bits[0], bits[1],
			table[4*i+0], table[4*i+1], table[4*i+2], table[4*i+3])
	}

	// Second level: use bits[2], bits[3] to reduce 4 -> 1
	return f.Lookup2(bits[2], bits[3], level1[0], level1[1], level1[2], level1[3])
}
