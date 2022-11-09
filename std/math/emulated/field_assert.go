package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// assertLimbsEqualitySlow is the main routine in the package. It asserts that the
// two slices of limbs represent the same integer value. This is also the most
// costly operation in the package as it does bit decomposition of the limbs.
func assertLimbsEqualitySlow(api frontend.API, l, r []frontend.Variable, nbBits, nbCarryBits uint) {

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
		carry = rsh(api, diff, int(nbBits), int(nbBits+nbCarryBits+1))
	}
	api.AssertIsEqual(carry, maxValueShift)
}

func rsh(api frontend.API, v frontend.Variable, startDigit, endDigit int) frontend.Variable {
	// if v is a constant, work with the big int value.
	if c, ok := api.Compiler().ConstantValue(v); ok {
		bits := make([]frontend.Variable, endDigit-startDigit)
		for i := 0; i < len(bits); i++ {
			bits[i] = c.Bit(i + startDigit)
		}
		return bits
	}

	bits, err := api.Compiler().NewHint(NBitsShifted, endDigit-startDigit, v, startDigit)
	if err != nil {
		panic(err)
	}

	// we compute 2 sums;
	// Σbi ensures that "ignoring" the lowest bits (< startDigit) still is a valid bit decomposition.
	// that is, it ensures that bits from startDigit to endDigit * corresponding coefficients (powers of 2 shifted)
	// are equal to the input variable
	// ΣbiRShift computes the actual result; that is, the Σ (2**i * b[i])
	Σbi := frontend.Variable(0)
	ΣbiRShift := frontend.Variable(0)

	cRShift := big.NewInt(1)
	c := big.NewInt(1)
	c.Lsh(c, uint(startDigit))

	for i := 0; i < len(bits); i++ {
		Σbi = api.Add(Σbi, api.Mul(bits[i], c))
		ΣbiRShift = api.Add(ΣbiRShift, api.Mul(bits[i], cRShift))
		c.Lsh(c, 1)
		cRShift.Lsh(cRShift, 1)
		api.AssertIsBoolean(bits[i])
	}

	// constraint Σ (2**i_shift * b[i]) == v
	api.AssertIsEqual(Σbi, v)
	return ΣbiRShift

}

// AssertLimbsEquality asserts that the limbs represent a same integer value (up
// to overflow). This method does not ensure that the values are equal modulo
// the field order. For strict equality, use AssertIsEqual.
func (f *Field[T]) AssertLimbsEquality(a, b *Element[T]) {
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

	// first, we check if we can compact the e and other; they could be using 8 limbs of 32bits
	// but with our snark field, we could express them in 2 limbs of 128bits, which would make bit decomposition
	// and limbs equality in-circuit (way) cheaper
	ca, cb, bitsPerLimb := f.compact(a, b)

	// slow path -- the overflows are different. Need to compare with carries.
	// TODO: we previously assumed that one side was "larger" than the other
	// side, but I think this assumption is not valid anymore
	if a.overflow > b.overflow {
		assertLimbsEqualitySlow(f.api, ca, cb, bitsPerLimb, a.overflow)
	} else {
		assertLimbsEqualitySlow(f.api, cb, ca, bitsPerLimb, b.overflow)
	}
}

// EnforceWidth enforces that the bitlength of the value is exactly the
// bitlength of the modulus. Any newly initialized variable should be
// constrained to ensure correct operations.
func (f *Field[T]) EnforceWidth(a *Element[T]) {
	_, aConst := f.constantValue(a)
	if aConst {
		if len(a.Limbs) != int(f.fParams.NbLimbs()) {
			panic("constant limb width doesn't match parametrized field")
		}
	}

	for i := range a.Limbs {
		// TODO @gbotrel why check all the limbs here? if len(e.Limbs) <= modulus
		// && last limb <= bits[lastLimbs] modulus, we're good ?
		limbNbBits := int(f.fParams.BitsPerLimb())
		if i == len(a.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((f.fParams.Modulus().BitLen() - 1) % int(f.fParams.BitsPerLimb())) + 1
		}
		// bits.ToBinary restricts the least significant NbDigits to be equal to
		// the limb value. This is sufficient to restrict for the bitlength and
		// we can discard the bits themselves.
		bits.ToBinary(f.api, a.Limbs[i], bits.WithNbDigits(limbNbBits))
	}
}

// AssertIsEqual ensures that a is equal to b modulo the modulus.
func (f *Field[T]) AssertIsEqual(a, b *Element[T]) {
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

// AssertIsEqualLessThan ensures that e is less or equal than e.
func (f *Field[T]) AssertIsLessEqualThan(e, a *Element[T]) {
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
