package sumcheck

import (
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/consensys/gnark/std/gkr/polynomial"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Verifier holds the methods relative to the verifier algorithm
type Verifier struct{}

// Verify returns true if and only the sumcheck proof is valid
func (v Verifier) Verify(claim fr.Element, proof Proof, bN, bG int) (result bool, qPrime, qL, qR []fr.Element, finalClaim fr.Element) {
	// Initalize the structures
	challenges := make([]fr.Element, len(proof.PolyCoeffs))
	var expectedValue fr.Element = claim
	var actualValue, r, zero, one, evalAtOne fr.Element
	one.SetOne()

	for i := 0; i < len(proof.PolyCoeffs); i++ {
		// Check P_i(0) + P_i(1) == expected
		actualValue = polynomial.EvaluatePolynomial(proof.PolyCoeffs[i], zero)
		evalAtOne = polynomial.EvaluatePolynomial(proof.PolyCoeffs[i], one)
		actualValue.Add(&actualValue, &evalAtOne)

		if expectedValue != actualValue {
			return false, nil, nil, nil, [4]uint64{0, 0, 0, 0}
		}
		// expectedValue = P_i(r)
		r = common.GetChallenge(proof.PolyCoeffs[i])

		challenges[i] = r
		expectedValue = polynomial.EvaluatePolynomial(proof.PolyCoeffs[i], r)
	}

	// A deep-copy to avoid reusing the same underlying slice for all writes
	qL = append([]fr.Element{}, challenges[:bG]...)
	qR = append([]fr.Element{}, challenges[bG:2*bG]...)
	qPrime = append([]fr.Element{}, challenges[2*bG:]...)

	// final confrontation omitted for now
	return true, qPrime, qL, qR, expectedValue
}
