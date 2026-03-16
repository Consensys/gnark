package gkr

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/polynomial"
)

// A SNARK gadget capable of verifying sumcheck proofs

// sumcheckLazyClaims is the Claims data structure on the verifier side. It is "lazy" in that it has to compute fewer things.
type sumcheckLazyClaims interface {
	varsNum() int
	degree(i int) int
	verifyFinalEval(api frontend.API, r []frontend.Variable, purportedValue frontend.Variable, proof []frontend.Variable) error
}

// sumcheckProof of a multi-sumcheck statement.
type sumcheckProof struct {
	PartialSumPolys []polynomial.Polynomial
	FinalEvalProof  []frontend.Variable
}

func verifySumcheck(api frontend.API, claims sumcheckLazyClaims, proof sumcheckProof, claimedSum frontend.Variable, degree int, t *transcript) error {
	r := make([]frontend.Variable, claims.varsNum())

	gJ := make(polynomial.Polynomial, degree+1)
	gJR := claimedSum

	for j := 0; j < claims.varsNum(); j++ {
		partialSumPoly := proof.PartialSumPolys[j]
		if len(partialSumPoly) != degree {
			return errors.New("malformed proof")
		}
		copy(gJ[1:], partialSumPoly)
		gJ[0] = api.Sub(gJR, partialSumPoly[0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)

		r[j] = t.getChallenge(proof.PartialSumPolys[j]...)

		gJR = polynomial.InterpolateLDE(api, r[j], gJ[:(degree+1)])
	}

	return claims.verifyFinalEval(api, r, gJR, proof.FinalEvalProof)
}
