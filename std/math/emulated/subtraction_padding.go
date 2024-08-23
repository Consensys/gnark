package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

// subPadding returns k*p for some k.
// Denote the padding d=(d[0], ..., d[nbLimbs]). When computing the difference
// of a and b by limb-wise subtraction
//
//	s = a - b = (a[0]-b[0], ..., a[nbLimbs]-b[nbLimbs])
//
// it may happen that some limbs underflow the snark scalar field and the limbs
// of s do not represent the actual difference a-b. However, when adding the
// padding d to every limb i.e.
//
//	s = a + d - b = (a[0]+d[0]-b[0], ..., a[nbLimbs]+d[nbLimbs]-b[nbLimbs])
//
// then no such underflow happens and s = a-b (mod p) as the padding is multiple
// of p.
func subPadding(modulus *big.Int, bitsPerLimbs uint, overflow uint, nbLimbs uint) []*big.Int {
	if modulus.Cmp(big.NewInt(0)) == 0 {
		panic("modulus is zero")
	}
	// first, we build a number nLimbs, such that nLimbs > b;
	// here b is defined by its bounds, that is b is an element with nbLimbs of (bitsPerLimbs+overflow)
	// so a number nLimbs > b, is simply taking the next power of 2 over this bound .
	nLimbs := make([]*big.Int, nbLimbs)
	for i := 0; i < len(nLimbs); i++ {
		nLimbs[i] = new(big.Int).SetUint64(1)
		nLimbs[i].Lsh(nLimbs[i], overflow+bitsPerLimbs)
	}

	// recompose n as the sum of the coefficients weighted by the limbs
	n := new(big.Int)
	if err := limbs.Recompose(nLimbs, bitsPerLimbs, n); err != nil {
		panic(fmt.Sprintf("recompose: %v", err))
	}
	// mod reduce n, and negate it
	n.Mod(n, modulus)
	n.Sub(modulus, n)

	// construct pad such that:
	// pad := n - neg(n mod p) == kp
	pad := make([]*big.Int, nbLimbs)
	for i := range pad {
		pad[i] = new(big.Int)
	}
	if err := limbs.Decompose(n, bitsPerLimbs, pad); err != nil {
		panic(fmt.Sprintf("decompose: %v", err))
	}
	for i := range pad {
		pad[i].Add(pad[i], nLimbs[i])
	}
	return pad
}

// subPaddingHint computes the padding for the subtraction of two numbers. It
// ensures that the padding is a multiple of the modulus. Can be used to avoid
// underflow.
//
// In case of fixed modulus use subPadding instead.
func subPaddingHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 4 {
		return fmt.Errorf("input must be at least four elements")
	}
	nbLimbs := int(inputs[0].Int64())
	bitsPerLimbs := uint(inputs[1].Uint64())
	overflow := uint(inputs[2].Uint64())
	retLimbs := int(inputs[3].Int64())
	if len(inputs[4:]) != nbLimbs {
		return fmt.Errorf("input length mismatch")
	}
	if len(outputs) != retLimbs {
		return fmt.Errorf("result does not fit into output")
	}
	pLimbs := inputs[4 : 4+nbLimbs]
	p := new(big.Int)
	if err := limbs.Recompose(pLimbs, bitsPerLimbs, p); err != nil {
		return fmt.Errorf("recompose modulus: %w", err)
	}
	padLimbs := subPadding(p, bitsPerLimbs, overflow, uint(nbLimbs))
	for i := range padLimbs {
		outputs[i].Set(padLimbs[i])
	}

	return nil
}

func (f *Field[T]) computeSubPaddingHint(overflow uint, nbLimbs uint, modulus *Element[T]) *Element[T] {
	// we compute the subtraction padding hint in-circuit. The padding has satisfy:
	// 1. padding % modulus = 0
	// 2. padding[i] >= (1 << (bits+overflow))
	// 3. padding[i] + a[i] < native_field for all valid a[i] (defined by overflow)
	var fp T
	inputs := []frontend.Variable{fp.NbLimbs(), fp.BitsPerLimb(), overflow, nbLimbs}
	inputs = append(inputs, modulus.Limbs...)
	// compute the actual padding value
	res, err := f.api.NewHint(subPaddingHint, int(nbLimbs), inputs...)
	if err != nil {
		panic(fmt.Sprintf("sub padding hint: %v", err))
	}
	maxLimb := new(big.Int).Lsh(big.NewInt(1), fp.BitsPerLimb()+overflow)
	maxLimb.Sub(maxLimb, big.NewInt(1))
	for i := range res {
		// we can check conditions 2 and 3 together by subtracting the maximum
		// value which can be subtracted from the padding. The result should not
		// underflow (in which case the width of the subtraction result could be
		// at least native_width-overflow) and should be nbBits+overflow+1 bits
		// wide (as expected padding is one bit wider than the maximum allowed
		// subtraction limb).
		f.checker.Check(f.api.Sub(res[i], maxLimb), int(fp.BitsPerLimb()+overflow+1))
	}

	// ensure that condition 1 holds
	padding := f.newInternalElement(res, overflow+1)
	f.checkZero(padding, modulus)
	return padding
}
