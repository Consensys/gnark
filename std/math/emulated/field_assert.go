package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// assertLimbsEqualitySlow is the main routine in the package. It asserts that the
// two slices of limbs represent the same integer value. This is also the most
// costly operation in the package as it does bit decomposition of the limbs.
func (f *Field[T]) assertLimbsEqualitySlow(api frontend.API, l, r []frontend.Variable, nbBits, nbCarryBits uint) {

	nbLimbs := max(len(l), len(r))
	maxValue := new(big.Int).Lsh(big.NewInt(1), nbBits+nbCarryBits)
	maxValueShift := new(big.Int).Lsh(big.NewInt(1), nbCarryBits)

	var carry frontend.Variable = 0
	for i := 0; i < nbLimbs; i++ {
		diff := api.Add(maxValue, carry)
		if i < len(l) {
			diff = api.Add(diff, l[i])
		}
		if i < len(r) {
			diff = api.Sub(diff, r[i])
		}
		if i > 0 {
			diff = api.Sub(diff, maxValueShift)
		}

		// carry is stored in the highest bits of diff[nbBits:nbBits+nbCarryBits+1]
		// we know that diff[:nbBits] are 0 bits, but still need to constrain them.
		// to do both; we do a "clean" right shift and only need to boolean constrain the carry part
		carry = f.rsh(diff, int(nbBits), int(nbBits+nbCarryBits+1))
	}
	api.AssertIsEqual(carry, maxValueShift)
}

func (f *Field[T]) rsh(v frontend.Variable, startDigit, endDigit int) frontend.Variable {
	// if v is a constant, work with the big int value.
	if c, ok := f.api.Compiler().ConstantValue(v); ok {
		bits := make([]frontend.Variable, endDigit-startDigit)
		for i := 0; i < len(bits); i++ {
			bits[i] = c.Bit(i + startDigit)
		}
		return bits
	}
	shifted, err := f.api.Compiler().NewHint(RightShift, 1, startDigit, v)
	if err != nil {
		panic(fmt.Sprintf("right shift: %v", err))
	}
	f.checker.Check(shifted[0], endDigit-startDigit)
	shift := new(big.Int).Lsh(big.NewInt(1), uint(startDigit))
	composed := f.api.Mul(shifted[0], shift)
	f.api.AssertIsEqual(composed, v)
	return shifted[0]
}

// AssertLimbsEquality asserts that the limbs represent a same integer value.
// This method does not ensure that the values are equal modulo the field order.
// For strict equality, use AssertIsEqual.
func (f *Field[T]) AssertLimbsEquality(a, b *Element[T]) {
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Mod(ba, f.fParams.Modulus())
		bb.Mod(bb, f.fParams.Modulus())
		if ba.Cmp(bb) != 0 {
			panic(fmt.Errorf("constant values are different: %s != %s", ba.String(), bb.String()))
		}
		return
	}

	// first, we check if we can compact a and b; they could be using 8 limbs of 32bits
	// but with our snark field, we could express them in 2 limbs of 128bits, which would make bit decomposition
	// and limbs equality in-circuit (way) cheaper
	ca, cb, bitsPerLimb := f.compact(a, b)

	// slow path -- the overflows are different. Need to compare with carries.
	// TODO: we previously assumed that one side was "larger" than the other
	// side, but I think this assumption is not valid anymore
	if a.overflow > b.overflow {
		f.assertLimbsEqualitySlow(f.api, ca, cb, bitsPerLimb, a.overflow)
	} else {
		f.assertLimbsEqualitySlow(f.api, cb, ca, bitsPerLimb, b.overflow)
	}
}

// enforceWidth enforces the width of the limbs. When modWidth is true, then the
// limbs are asserted to be the width of the modulus (highest limb may be less
// than full limb width). Otherwise, every limb is assumed to have same width
// (defined by the field parameter).
func (f *Field[T]) enforceWidth(a *Element[T], modWidth bool) {
	if _, aConst := f.constantValue(a); aConst {
		if len(a.Limbs) != int(f.fParams.NbLimbs()) {
			panic("constant limb width doesn't match parametrized field")
		}
	}
	if modWidth && len(a.Limbs) != int(f.fParams.NbLimbs()) {
		panic("enforcing modulus width element with inexact number of limbs")
	}

	for i := range a.Limbs {
		limbNbBits := int(f.fParams.BitsPerLimb())
		if modWidth && i == len(a.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((f.fParams.Modulus().BitLen() - 1) % int(f.fParams.BitsPerLimb())) + 1
		}
		f.checker.Check(a.Limbs[i], limbNbBits)
	}
}

// AssertIsEqual ensures that a is equal to b modulo the modulus.
func (f *Field[T]) AssertIsEqual(a, b *Element[T]) {
	// we omit width assertion as it is done in Sub below
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Mod(ba, f.fParams.Modulus())
		bb.Mod(bb, f.fParams.Modulus())
		if ba.Cmp(bb) != 0 {
			panic(fmt.Sprintf("%s != %s", ba, bb))
		}
		return
	}

	diff := f.Sub(b, a)

	// we compute k such that diff / p == k
	// so essentially, we say "I know an element k such that k*p == diff"
	// hence, diff == 0 mod p
	p := f.Modulus()
	k, err := f.computeQuoHint(diff)
	if err != nil {
		panic(fmt.Sprintf("hint error: %v", err))
	}

	kp := f.reduceAndOp(f.mul, f.mulPreCond, k, p)

	f.AssertLimbsEquality(diff, kp)
}

// AssertIsLessOrEqual ensures that e is less or equal than a.
func (f *Field[T]) AssertIsLessOrEqual(e, a *Element[T]) {
	// we omit conditional width assertion as is done in ToBits below
	if e.overflow+a.overflow > 0 {
		panic("inputs must have 0 overflow")
	}
	eBits := f.ToBits(e)
	aBits := f.ToBits(a)
	ff := func(xbits, ybits []frontend.Variable) []frontend.Variable {
		diff := len(xbits) - len(ybits)
		ybits = append(ybits, make([]frontend.Variable, diff)...)
		for i := len(ybits) - diff - 1; i < len(ybits); i++ {
			ybits[i] = 0
		}
		return ybits
	}
	if len(eBits) > len(aBits) {
		aBits = ff(eBits, aBits)
	} else {
		eBits = ff(aBits, eBits)
	}
	p := make([]frontend.Variable, len(eBits)+1)
	p[len(eBits)] = 1
	for i := len(eBits) - 1; i >= 0; i-- {
		v := f.api.Mul(p[i+1], eBits[i])
		p[i] = f.api.Select(aBits[i], v, p[i+1])
		t := f.api.Select(aBits[i], 0, p[i+1])
		l := f.api.Sub(1, t, eBits[i])
		ll := f.api.Mul(l, eBits[i])
		f.api.AssertIsEqual(ll, 0)
	}
}
