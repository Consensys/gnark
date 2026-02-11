package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/bits"
)

// ToBits returns the bit representation of the Element in little-endian (LSB
// first) order. The returned bits are constrained to be 0-1. The number of
// returned bits is nbLimbs*nbBits+overflow. To obtain the bits of the canonical
// representation of Element, use method [Field.ToBitsCanonical].
//
// The bit decomposition is cached in the Element to avoid redundant computation
// when the same element is decomposed multiple times.
func (f *Field[T]) ToBits(a *Element[T]) []frontend.Variable {
	f.enforceWidthConditional(a)
	ba, aConst := f.constantValue(a)
	if aConst {
		res := make([]frontend.Variable, f.fParams.BitsPerLimb()*f.fParams.NbLimbs())
		for i := range res {
			res[i] = ba.Bit(i)
		}
		return res
	}

	// Check if we have cached bits for this element
	if a.bitsDecomposition != nil {
		// Return a copy to prevent callers from mutating the cached bits
		res := make([]frontend.Variable, len(a.bitsDecomposition))
		copy(res, a.bitsDecomposition)
		return res
	}

	var carry frontend.Variable = 0
	var fullBits []frontend.Variable
	var limbBits []frontend.Variable
	for i := 0; i < len(a.Limbs); i++ {
		limbBits = bits.ToBinary(f.api, f.api.Add(a.Limbs[i], carry), bits.WithNbDigits(int(f.fParams.BitsPerLimb()+a.overflow)))
		fullBits = append(fullBits, limbBits[:f.fParams.BitsPerLimb()]...)
		if a.overflow > 0 {
			carry = bits.FromBinary(f.api, limbBits[f.fParams.BitsPerLimb():])
		}
	}
	fullBits = append(fullBits, limbBits[f.fParams.BitsPerLimb():f.fParams.BitsPerLimb()+a.overflow]...)

	// Cache the bits in the element for future use
	a.bitsDecomposition = fullBits

	// Record operation for profiling
	profile.RecordOperation("emulated.ToBits", 4*len(fullBits))
	return fullBits
}

// ToBitsCanonical represents the unique bit representation in the canonical
// format (less that the modulus).
func (f *Field[T]) ToBitsCanonical(a *Element[T]) []frontend.Variable {
	nbBits := f.fParams.Modulus().BitLen()
	// when the modulus is a power of 2, then we can remove the most significant
	// bit as it is always zero.
	if f.fParams.Modulus().TrailingZeroBits() == uint(nbBits-1) {
		nbBits--
	}

	// Fast path: if already strictly reduced, just get bits
	if a.modReduced {
		bts := f.ToBits(a)
		return bts[:nbBits]
	}

	// Reduce the element first using strict reduction (always performs mulMod).
	// This ensures the value is actually reduced mod p, not just has overflow=0.
	ca := f.reduce(a, true)

	// Get bits of reduced element
	caBits := f.ToBits(ca)

	// Get bits of modulus-1 (this is cached as a constant, so ToBits is cheap)
	modPrev := f.modulusPrev()
	modPrevBits := f.ToBits(modPrev)

	// Now perform the less-or-equal check using the bits we already have.
	// This avoids calling ToBits again on the same element (which is what
	// the original ReduceStrict + AssertIsInRange path would do).
	padBits := func(xbits, ybits []frontend.Variable) []frontend.Variable {
		diff := len(xbits) - len(ybits)
		ybits = append(ybits, make([]frontend.Variable, diff)...)
		for i := len(ybits) - diff; i < len(ybits); i++ {
			ybits[i] = 0
		}
		return ybits
	}
	eBits := caBits
	aBits := modPrevBits
	if len(eBits) > len(aBits) {
		aBits = padBits(eBits, aBits)
	} else {
		eBits = padBits(aBits, eBits)
	}

	// Perform the comparison: assert ca <= modulusPrev
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

	profile.RecordOperation("emulated.ToBitsCanonical", 4*(len(eBits)+len(aBits)))
	return caBits[:nbBits]
}

// FromBits returns a new Element given the bits is little-endian order.
func (f *Field[T]) FromBits(bs ...frontend.Variable) *Element[T] {
	nbLimbs := (uint(len(bs)) + f.fParams.BitsPerLimb() - 1) / f.fParams.BitsPerLimb()
	limbs := make([]frontend.Variable, nbLimbs)
	for i := uint(0); i < nbLimbs-1; i++ {
		limbs[i] = bits.FromBinary(f.api, bs[i*f.fParams.BitsPerLimb():(i+1)*f.fParams.BitsPerLimb()])
	}
	limbs[nbLimbs-1] = bits.FromBinary(f.api, bs[(nbLimbs-1)*f.fParams.BitsPerLimb():])
	return f.newInternalElement(limbs, 0)
}
