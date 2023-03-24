package polynomial

import (
	"github.com/consensys/gnark/std/gkr/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func init() {
	initLagrangePolynomials()
}

// GetLagrangePolynomial returns a precalculated array representing the univariate
// lagrange polynomials on domainSize.
func GetLagrangePolynomial(domainSize int) [][]fr.Element {
	return lagrangePolynomials[domainSize]
}

var lagrangePolynomials [][][]fr.Element

const maxDomainSize int = 12

func initLagrangePolynomials() {
	lagrangePolynomials = make([][][]fr.Element, maxDomainSize+1)
	for i := 0; i < maxDomainSize+1; i++ {
		lagrangePolynomials[i] = LagrangeCoefficient(i)
	}
}

// EvaluatePolynomial evaluates a polynomial from its coefficients
func EvaluatePolynomial(coeffs []fr.Element, x fr.Element) fr.Element {
	var result fr.Element
	result.Set(&coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result.Mul(&result, &x)
		result.Add(&result, &coeffs[i])
	}
	return result
}

// LagrangeCoefficient returns the matrix of Lagrange polynomials for the domain [[0; n - 1]]
func LagrangeCoefficient(domainSize int) [][]fr.Element {
	// Declare the binomials
	binomials := make([][2]fr.Element, domainSize)
	for i := uint64(0); i < uint64(domainSize); i++ {
		var interceipts fr.Element
		interceipts.SetUint64(i)
		binomials[i][0].Neg(&interceipts)
		binomials[i][1].SetOne()
	}

	result := make([][]fr.Element, domainSize)

	for l := 0; l < domainSize; l++ {
		// Each iteration computes the the l-th Lagrange polynomial
		// on range [0, domainSize-1]
		accumulator := make([]fr.Element, domainSize)
		accumulator[0].SetOne()
		var tmp fr.Element

		for i := 0; i < domainSize; i++ {
			if i == l {
				// Skip the monomial
				continue
			}
			// Computes X(X-1)(X-2)..(X-i)..(X-domainSize-1) for i != l
			updated := make([]fr.Element, domainSize)
			for j := 0; j < domainSize; j++ {
				for k := 0; k < common.Min(2, domainSize-j); k++ {
					tmp.Set(&accumulator[j])
					tmp.Mul(&tmp, &binomials[i][k])
					updated[j+k].Add(&updated[j+k], &tmp)
				}
			}
			accumulator = updated
		}
		// Normalize the polynomial to have P(l) = 1.
		// Order to do so, we compute normalizationFactor = P(l),
		// and divide each coefficent by normalizationFactor
		var lFieldElement fr.Element
		lFieldElement.SetUint64(uint64(l))
		normalizationFactor := EvaluatePolynomial(accumulator, lFieldElement)
		// Now divide all coefficients
		normalizationFactor.Inverse(&normalizationFactor)
		for i := range accumulator {
			accumulator[i].Mul(&accumulator[i], &normalizationFactor)
		}
		result[l] = accumulator
	}

	return result
}

// InterpolateOnRange performs the interpolation of the given list of elements
// On the range [0, 1,..., len(values) - 1]
func InterpolateOnRange(values []fr.Element) []fr.Element {
	nEvals := len(values)
	lagrange := GetLagrangePolynomial(nEvals)
	result := make([]fr.Element, nEvals)
	var tmp fr.Element

	for i := range values {
		for j := range lagrange[i] {
			tmp.Set(&lagrange[i][j])
			tmp.Mul(&tmp, &values[i])
			result[j].Add(&result[j], &tmp)
		}
	}

	return result
}
