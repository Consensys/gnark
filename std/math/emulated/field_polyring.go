package emulated

import (
	"fmt"
	"math/big"
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
//   - irr - the irreducible polynomial defining the ring, i.e. the modulus for
//     the Euclidean division. Treated as a constant.
//   - r - the product reduced modulo irr, i.e. the remainder. This is the
//     result returned to the caller.
//   - q - the quotient of the product divided by irr.
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

	fmt.Printf("inputs: %v\n", inputs)
	fmt.Printf("modPoly: %v\n", modPoly)

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

	fmt.Printf("product: %v\n", product)
	fmt.Printf("quotient: %v\n", quotient)
	fmt.Printf("remainder: %v\n", remainder)

	return quotient, remainder, nil
}
