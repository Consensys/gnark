package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// recompose takes the limbs in inputs and combines them into res. It errors if
// inputs is uninitialized or zero-length and if the result is uninitialized.
//
// The following holds
//
//	res = \sum_{i=0}^{len(inputs)} inputs[i] * 2^{nbBits * i}
func recompose(inputs []*big.Int, nbBits uint, res *big.Int) error {
	if len(inputs) == 0 {
		return fmt.Errorf("zero length slice input")
	}
	if res == nil {
		return fmt.Errorf("result not initialized")
	}
	res.SetUint64(0)
	for i := range inputs {
		res.Lsh(res, nbBits)
		res.Add(res, inputs[len(inputs)-i-1])
	}
	// TODO @gbotrel mod reduce ?
	return nil
}

// decompose decomposes the input into res as integers of width nbBits. It
// errors if the decomposition does not fit into res or if res is uninitialized.
//
// The following holds
//
//	input = \sum_{i=0}^{len(res)} res[i] * 2^{nbBits * i}
func decompose(input *big.Int, nbBits uint, res []*big.Int) error {
	// limb modulus
	if input.BitLen() > len(res)*int(nbBits) {
		return fmt.Errorf("decomposed integer does not fit into res")
	}
	for _, r := range res {
		if r == nil {
			return fmt.Errorf("result slice element uninitalized")
		}
	}
	base := new(big.Int).Lsh(big.NewInt(1), nbBits)
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i].Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}

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
func subPadding[T FieldParams](overflow uint, nbLimbs uint) []*big.Int {
	var fp T
	p := fp.Modulus()
	bitsPerLimbs := fp.BitsPerLimb()

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
	if err := recompose(nLimbs, bitsPerLimbs, n); err != nil {
		panic(fmt.Sprintf("recompose: %v", err))
	}
	// mod reduce n, and negate it
	n.Mod(n, p)
	n.Sub(p, n)

	// construct pad such that:
	// pad := n - neg(n mod p) == kp
	pad := make([]*big.Int, nbLimbs)
	for i := range pad {
		pad[i] = new(big.Int)
	}
	if err := decompose(n, bitsPerLimbs, pad); err != nil {
		panic(fmt.Sprintf("decompose: %v", err))
	}
	for i := range pad {
		pad[i].Add(pad[i], nLimbs[i])
	}
	return pad
}

// compact returns parameters which allow for most optimal regrouping of
// limbs. In regrouping the limbs, we encode multiple existing limbs as a linear
// combination in a single new limb.
// compact returns a and b minimal (in number of limbs) representation that fits in the snark field
func (f *Field[T]) compact(a, b Element[T]) (ac, bc []frontend.Variable, bitsPerLimb uint) {
	maxOverflow := max(a.overflow, b.overflow)
	// subtract one bit as can not potentially use all bits of Fr and one bit as
	// grouping may overflow
	maxNbBits := uint(f.api.Compiler().FieldBitLen()) - 2 - maxOverflow
	groupSize := maxNbBits / a.fParams.BitsPerLimb()
	if groupSize == 0 {
		// no space for compact
		return a.Limbs, b.Limbs, a.fParams.BitsPerLimb()
	}

	bitsPerLimb = a.fParams.BitsPerLimb() * groupSize

	ac = f.compactLimbs(a, groupSize, bitsPerLimb)
	bc = f.compactLimbs(b, groupSize, bitsPerLimb)
	return
}

// compactLimbs perform the regrouping of limbs between old and new parameters.
func (f *Field[T]) compactLimbs(e Element[T], groupSize, bitsPerLimb uint) []frontend.Variable {
	if f.fParams.BitsPerLimb() == bitsPerLimb {
		return e.Limbs
	}
	nbLimbs := (uint(len(e.Limbs)) + groupSize - 1) / groupSize
	r := make([]frontend.Variable, nbLimbs)
	coeffs := make([]*big.Int, groupSize)
	one := big.NewInt(1)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
		coeffs[i].Lsh(one, e.fParams.BitsPerLimb()*uint(i))
	}
	for i := uint(0); i < nbLimbs; i++ {
		r[i] = uint(0)
		for j := uint(0); j < groupSize && i*groupSize+j < uint(len(e.Limbs)); j++ {
			r[i] = f.api.Add(r[i], f.api.Mul(coeffs[j], e.Limbs[i*groupSize+j]))
		}
	}
	return r
}
