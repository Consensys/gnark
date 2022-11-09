package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// ToBinary returns the bit representation of the Element in little-endian (LSB
// first) order. The returned bits are constrained to be 0-1. The number of
// returned bits is nbLimbs*nbBits+overflow. To obtain the bits of the canonical
// representation of Element, reduce Element first and take less significant
// bits corresponding to the bitwidth of the emulated modulus.
func (f *Field[T]) ToBits(a *Element[T]) []frontend.Variable {
	ba, aConst := f.constantValue(a)
	if aConst {
		return f.api.ToBinary(ba, int(f.fParams.BitsPerLimb()*f.fParams.NbLimbs()))
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
	return fullBits
}

func (f *Field[T]) FromBits(bs ...frontend.Variable) *Element[T] {
	nbLimbs := (uint(len(bs)) + f.fParams.BitsPerLimb() - 1) / f.fParams.BitsPerLimb()
	limbs := make([]frontend.Variable, nbLimbs)
	for i := uint(0); i < nbLimbs-1; i++ {
		limbs[i] = bits.FromBinary(f.api, bs[i*f.fParams.BitsPerLimb():(i+1)*f.fParams.BitsPerLimb()])
	}
	limbs[nbLimbs-1] = bits.FromBinary(f.api, bs[(nbLimbs-1)*f.fParams.BitsPerLimb():])
	return newElementLimbs[T](limbs, 0)
}
