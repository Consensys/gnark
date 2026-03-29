package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

// Represents an element of a polynomial ring over the emulated field.
type Poly[T FieldParams] []*Element[T]

// polyRingMulCheck represents a polynomial product check in a polynomial
// ring. Instead of computing the product and reducing it where called,
// we compute the result using a hint and return it. Result is stored for
// correctness check later to share the verifier challenge computation.
//
// We store the values poly, irr, r, q. They are as follows:
//   - poly - the input polynomials whose product we are checking. Each
//     polynomial is represented as a slice of [Element] coefficients. Elements
//     have to be reduced.
//   - mod - the polynomial defining the ring, i.e. the modulus for the Euclidean
//     division. Treated as a constant.
//   - r - the product reduced modulo mod, i.e. the remainder. This is the
//     result returned to the caller.
//   - q - the quotient of the product divided by mod.
//
// Given these values, the following holds as an identity of polynomials over
// the emulated field:
//
//	∏_i inputs_i = r + q * mod
//
// For asserting that the previous identity holds, we evaluate both sides at a
// single random challenge point α obtained via commitment to all coefficients.
// If a polynomial f has coefficient elements (f_0, ..., f_n), its evaluation is
//
//	f(α) = ∑_i f_i(α) * α^i,
//
// where each f_i(α) is itself the Schwartz-Zippel evaluation of the limb
// polynomial of the emulated element f_i. The product check then becomes
//
//	∏_i inputs_i(α) = r(α) + q(α) * mod(α),
//
// which can be verified at a single random point.
type polyRingMulCheck[T FieldParams] struct {
	f *Field[T]
	// ∏_i inputs_i = r + q * mod
	inputs []Poly[T] // input polynomials
	mod    Poly[T]   // irreducible polynomial defining the ring
	r      Poly[T]   // remainder
	q      Poly[T]   // quotient
}

// CallPolyRingMulHint computes a polynomial product check in a polynomial ring,
// returns the remainder (reduced result) and the quotient. The computation
// is performed inside a hint, so it is the callers responsibility to perform
// the deferred polynomial ring multiplication check.
func (f *Field[T]) CallPolyRingMulHint(inputs []Poly[T], mod Poly[T]) (quo, rem Poly[T], err error) {
	nbLimbs, nbBits := int(f.fParams.NbLimbs()), f.fParams.BitsPerLimb()

	// total number of terms for all input polynomials
	nbTerms := 0
	// loop through inputs to compute the number of terms
	for _, inputPoly := range inputs {
		// add degree of each input polynomial
		nbTerms += len(inputPoly)
	}

	// metadata for hint inputs
	nbPoly := len(inputs)
	nbTermsLimbs := nbTerms * nbLimbs
	nbModTermsLimbs := len(mod) * nbLimbs

	// metadata for outputs
	modDegree := len(mod) - 1
	nbRemLimbs := modDegree * nbLimbs
	totalDegree := nbTerms - nbPoly
	// q degree is total degree minus the degree of the modulus polynomial
	qDegree := totalDegree - modDegree
	nbQTermsLimbs := (1 + qDegree) * nbLimbs

	// Polynomials serialised as nbTerms|...terms. hintInputs contains serialisation of,
	// in order: nbBits|nbLimbs|nbPoly|fieldMod|...inputs|modPoly, where inputs and mod are serialised as polynomials
	hintInputs := make([]frontend.Variable, 0, 4+(nbPoly+nbTermsLimbs)+(1+nbModTermsLimbs))

	hintInputs = append(hintInputs, nbBits, nbLimbs, nbPoly, *f.fParams.Modulus())

	// loop through inputs to compute the number of terms
	for _, inputPoly := range inputs {
		// serialised as nbTerms|...terms
		// add degree of each input polynomial
		hintInputs = append(hintInputs, len(inputPoly))
		// append each term from inputPoly polynomial
		for _, coeff := range inputPoly {
			hintInputs = append(hintInputs, coeff.Limbs...)
		}
	}

	hintInputs = append(hintInputs, len(mod))
	// append mod terms
	for _, coeff := range mod {
		hintInputs = append(hintInputs, coeff.Limbs...)
	}

	// call
	ret, err := f.api.NewHint(polyRingMulHint, 1+nbQTermsLimbs+1+nbRemLimbs, hintInputs...)

	if err != nil {
		return nil, nil, err
	}

	// unpack quotient: skip nbQTerms header, then read (1+qDegree) terms of nbLimbs each
	quo = make(Poly[T], 1+qDegree)
	retPtr := 1 // skip nbQTerms
	for i := range quo {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		quo[i] = f.packLimbs(termLimbs, false)
	}

	// unpack remainder: skip nbRemTerms header, then read (len(mod)-1) terms of nbLimbs each
	retPtr++ // skip nbRemTerms
	rem = make(Poly[T], len(mod)-1)
	for i := range rem {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		rem[i] = f.packLimbs(termLimbs, true)
	}

	f.deferredPolyChecks = append(f.deferredPolyChecks, polyRingMulCheck[T]{
		f:      f,
		inputs: inputs,
		mod:    mod,
		r:      rem,
		q:      quo,
	})

	return quo, rem, nil
}

// polyRingMulHint computes the multivariate evaluation as a hint. Should not be
// called directly, but rather through [Field.callPolyRingMulHint] method which
// handles the input packing and output unpacking.
func polyRingMulHint(mod *big.Int, inputs, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbPoly := int(inputs[2].Int64())
	fieldMod := new(big.Int).Set(inputs[3])

	// extract the input polynomials
	inputsPolys := make([][]*big.Int, nbPoly)
	ptr := 4

	for i := 0; i < nbPoly; i++ {
		nbTerms := int(inputs[ptr].Int64())
		ptr++
		inputsPolys[i] = make([]*big.Int, nbTerms)
		for j := 0; j < nbTerms; j++ {
			coeffLimbs := inputs[ptr : ptr+nbLimbs]
			ptr += nbLimbs
			val := new(big.Int)
			if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
				return fmt.Errorf("recompose input[%d][%d]: %w", i, j, err)
			}
			inputsPolys[i][j] = val
		}
	}

	nbModPolyTerms := int(inputs[ptr].Int64())
	ptr++
	modPoly := make([]*big.Int, nbModPolyTerms)
	for j := 0; j < nbModPolyTerms; j++ {
		coeffLimbs := inputs[ptr : ptr+nbLimbs]
		ptr += nbLimbs
		val := new(big.Int)
		if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
			return fmt.Errorf("recompose mod polynomial[%d]: %w", j, err)
		}
		modPoly[j] = val
	}

	// multiply inputs and divide by modPoly to obtain quotient and remainder
	q, r, err := polyRingMul(fieldMod, inputsPolys, modPoly)
	if err != nil {
		return fmt.Errorf("polyRingMul: %w", err)
	}

	// serialize outputs: nbQTerms | q limbs... | nbRemTerms | r limbs...
	nbBitsU := uint(nbBits)
	outptr := 0
	outputs[outptr].SetInt64(int64(len(q)))
	outptr++
	for _, coeff := range q {
		coeffLimbs := make([]*big.Int, nbLimbs)
		for i := range coeffLimbs {
			coeffLimbs[i] = new(big.Int)
		}
		if err := limbs.Decompose(coeff, nbBitsU, coeffLimbs); err != nil {
			return fmt.Errorf("decompose quotient coeff: %w", err)
		}
		copy(outputs[outptr:outptr+nbLimbs], coeffLimbs)
		outptr += nbLimbs
	}
	outputs[outptr].SetInt64(int64(len(r)))
	outptr++
	for _, coeff := range r {
		coeffLimbs := make([]*big.Int, nbLimbs)
		for i := range coeffLimbs {
			coeffLimbs[i] = new(big.Int)
		}
		if err := limbs.Decompose(coeff, nbBitsU, coeffLimbs); err != nil {
			return fmt.Errorf("decompose remainder coeff: %w", err)
		}
		copy(outputs[outptr:outptr+nbLimbs], coeffLimbs)
		outptr += nbLimbs
	}

	return nil
}

// polyRingMul multiplies all polynomials in inputs and divides the product
// by modPoly using polynomial Euclidean division. Coefficients are reduced
// modulo fieldMod (the emulated field prime).
func polyRingMul(fieldMod *big.Int, inputs [][]*big.Int, modPoly []*big.Int) (q, r []*big.Int, err error) {
	if len(inputs) == 0 {
		return nil, nil, fmt.Errorf("polyRingMul: no input polynomials")
	}
	if len(modPoly) == 0 {
		return nil, nil, fmt.Errorf("polyRingMul: modulus polynomial is empty")
	}

	// multiply all polynomials in inputs
	product := make([]*big.Int, len(inputs[0]))
	for i, c := range inputs[0] {
		product[i] = new(big.Int).Mod(c, fieldMod)
	}
	for k := 1; k < len(inputs); k++ {
		b := inputs[k]
		result := make([]*big.Int, len(product)+len(b)-1)
		for i := range result {
			result[i] = new(big.Int)
		}
		for i, ci := range product {
			for j, cj := range b {
				term := new(big.Int).Mul(ci, cj)
				result[i+j].Add(result[i+j], term)
				result[i+j].Mod(result[i+j], fieldMod)
			}
		}
		product = result
	}

	// euclidean division: product = quotient * modPoly + remainder
	divisorDeg := len(modPoly) - 1

	// if product has lower degree than modPoly, quotient is 0 and remainder is product
	if len(product)-1 < divisorDeg {
		remainder := make([]*big.Int, divisorDeg)
		for i := range remainder {
			if i < len(product) {
				remainder[i] = new(big.Int).Set(product[i])
			} else {
				remainder[i] = new(big.Int)
			}
		}
		return []*big.Int{new(big.Int)}, remainder, nil
	}

	// leading coefficient inverse of modPoly modulo field modulus
	lcInv := new(big.Int).ModInverse(modPoly[divisorDeg], fieldMod)
	if lcInv == nil {
		return nil, nil, fmt.Errorf("polyRingMul: leading coefficient of modulus polynomial is not invertible")
	}

	dividend := make([]*big.Int, len(product))
	for i, c := range product {
		dividend[i] = new(big.Int).Set(c)
	}

	qDeg := len(product) - 1 - divisorDeg
	quotient := make([]*big.Int, qDeg+1)
	for i := range quotient {
		quotient[i] = new(big.Int)
	}

	for len(dividend) >= len(modPoly) {
		d := len(dividend) - len(modPoly)
		// leading quotient term at degree d
		lc := new(big.Int).Mul(dividend[len(dividend)-1], lcInv)
		lc.Mod(lc, fieldMod)
		quotient[d].Set(lc)
		// subtract lc * x^d * modPoly from dividend
		for i, c := range modPoly {
			term := new(big.Int).Mul(lc, c)
			dividend[i+d].Sub(dividend[i+d], term)
			dividend[i+d].Mod(dividend[i+d], fieldMod)
		}
		// trim leading zeros
		for len(dividend) > 0 && dividend[len(dividend)-1].Sign() == 0 {
			dividend = dividend[:len(dividend)-1]
		}
	}

	// pad remainder to divisorDeg terms
	remainder := make([]*big.Int, divisorDeg)
	for i := range remainder {
		if i < len(dividend) {
			remainder[i] = new(big.Int).Set(dividend[i])
		} else {
			remainder[i] = new(big.Int)
		}
	}

	return quotient, remainder, nil
}

func (f *Field[T]) MakePoly(coeffs []interface{}) Poly[T] {
	nativeMod := f.api.Compiler().Field()

	poly := make(Poly[T], len(coeffs))

	for i, coeff := range coeffs {
		emCoeff_ := ValueOf[T](coeff)
		emCoeff := &emCoeff_
		emCoeff.Initialize(nativeMod)
		poly[i] = emCoeff
	}

	return poly
}
