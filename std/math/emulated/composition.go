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
//    res = \sum_{i=0}^{len(inputs)} inputs[i] * 2^{nbBits * i}
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
	return nil
}

// decompose decomposes the input into res as integers of width nbBits. It
// errors if the decomposition does not fit into res or if res is uninitialized.
//
// The following holds
//
//    input = \sum_{i=0}^{len(res)} res[i] * 2^{nbBits * i}
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
		res[i] = new(big.Int).Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}

// subPadding returns k*p for some k.
// Denote the padding d=(d[0], ..., d[nbLimbs]). When computing the difference
// of a and b by limb-wise subtraction
//
//     s = a - b = (a[0]-b[0], ..., a[nbLimbs]-b[nbLimbs])
//
// it may happen that some limbs underflow the snark scalar field and the limbs
// of s do not represent the actual difference a-b. However, when adding the
// padding d to every limb i.e.
//
//     s = a + d - b = (a[0]+d[0]-b[0], ..., a[nbLimbs]+d[nbLimbs]-b[nbLimbs])
//
// then no such underflow happens and s = a-b (mod p) as the padding is multiple
// of p.
func subPadding(params *field, current_overflow uint, nbLimbs uint) []*big.Int {
	padLimbs := make([]*big.Int, nbLimbs)
	for i := 0; i < len(padLimbs); i++ {
		padLimbs[i] = new(big.Int).Lsh(big.NewInt(1), uint(current_overflow)+params.limbSize)
	}
	pad := new(big.Int)
	if err := recompose(padLimbs, params.limbSize, pad); err != nil {
		panic(fmt.Sprintf("recompose: %v", err))
	}
	pad.Mod(pad, params.r)
	pad.Sub(params.r, pad)
	ret := make([]*big.Int, nbLimbs)
	for i := range ret {
		ret[i] = new(big.Int)
	}
	if err := decompose(pad, params.limbSize, ret); err != nil {
		panic(fmt.Sprintf("decompose: %v", err))
	}
	for i := range ret {
		ret[i].Add(ret[i], padLimbs[i])
	}
	return ret
}

// regroupParams returns parameters which allow for most optimal regrouping of
// limbs. In regrouping the limbs, we encode multiple existing limbs as a linear
// combination in a single new limb.
func regroupParams(params *field, nbNativeBits, nbMaxOverflow uint) *field {
	// subtract one bit as can not potentially use all bits of Fr and one bit as
	// grouping may overflow
	maxFit := nbNativeBits - 2
	groupSize := (maxFit - nbMaxOverflow) / params.limbSize
	if groupSize == 0 {
		// not sufficient space for regroup, return the same parameters.
		return params
	}
	nbRegroupBits := params.limbSize * groupSize
	nbRegroupLimbs := (params.nbLimbs + groupSize) / groupSize
	return &field{
		r:           params.r,
		hasInverses: params.hasInverses,
		nbLimbs:     nbRegroupLimbs,
		limbSize:    nbRegroupBits,
	}
}

// regroupLimbs perform the regrouping of limbs between old and new parameters.
func regroupLimbs(api frontend.API, params, regroupParams *field, limbs []frontend.Variable) []frontend.Variable {
	if params.limbSize == regroupParams.limbSize {
		// not regrouping
		return limbs
	}
	if regroupParams.limbSize%params.limbSize != 0 {
		panic("regroup bitwidth must be multiple of initial bitwidth")
	}
	groupSize := regroupParams.limbSize / params.limbSize
	nbLimbs := (uint(len(limbs)) + groupSize - 1) / groupSize
	regrouped := make([]frontend.Variable, nbLimbs)
	coeffs := make([]*big.Int, groupSize)
	one := big.NewInt(1)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
		coeffs[i].Lsh(one, params.limbSize*uint(i))
	}
	for i := uint(0); i < nbLimbs; i++ {
		regrouped[i] = uint(0)
		for j := uint(0); j < groupSize && i*groupSize+j < uint(len(limbs)); j++ {
			regrouped[i] = api.Add(regrouped[i], api.Mul(coeffs[j], limbs[i*groupSize+j]))
		}
	}
	return regrouped
}
