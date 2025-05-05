package gkr_api

import (
	"errors"
	"strconv"

	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
)

// sumcheckLazyClaims is the Claims data structure on the verifier side. It is "lazy" in that it has to compute fewer things.
type sumcheckLazyClaims interface {
	claimsNum() int                                                      // claimsNum = m
	varsNum() int                                                        // varsNum = n
	combinedSum(api frontend.API, a frontend.Variable) frontend.Variable // combinedSum returns c = ∑_{1≤j≤m} aʲ⁻¹cⱼ
	degree(i int) int                                                    // degree of the total claim in the i'th variable
	verifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff, purportedValue frontend.Variable, proof []frontend.Variable) error
}

// sumcheckProof of a multi-sumcheck statement.
type sumcheckProof struct {
	PartialSumPolys []polynomial.Polynomial
	FinalEvalProof  []frontend.Variable
}

func setupTranscript(api frontend.API, claimsNum int, varsNum int, settings *fiatshamir.Settings) ([]string, error) {
	numChallenges := varsNum
	if claimsNum >= 2 {
		numChallenges++
	}
	challengeNames := make([]string, numChallenges)
	if claimsNum >= 2 {
		challengeNames[0] = settings.Prefix + "comb"
	}
	prefix := settings.Prefix + "pSP."
	for i := 0; i < varsNum; i++ {
		challengeNames[i+numChallenges-varsNum] = prefix + strconv.Itoa(i)
	}
	if settings.Transcript == nil {
		settings.Transcript = fiatshamir.NewTranscript(api, settings.Hash, challengeNames)
	}

	return challengeNames, settings.Transcript.Bind(challengeNames[0], settings.BaseChallenges)
}

func next(transcript *fiatshamir.Transcript, bindings []frontend.Variable, remainingChallengeNames *[]string) (frontend.Variable, error) {
	challengeName := (*remainingChallengeNames)[0]
	if err := transcript.Bind(challengeName, bindings); err != nil {
		return nil, err
	}

	res, err := transcript.ComputeChallenge(challengeName)
	*remainingChallengeNames = (*remainingChallengeNames)[1:]
	return res, err
}

func verifySumcheck(api frontend.API, claims sumcheckLazyClaims, proof sumcheckProof, transcriptSettings fiatshamir.Settings) error {

	remainingChallengeNames, err := setupTranscript(api, claims.claimsNum(), claims.varsNum(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return err
	}

	var combinationCoeff frontend.Variable

	if claims.claimsNum() >= 2 {
		if combinationCoeff, err = next(transcript, []frontend.Variable{}, &remainingChallengeNames); err != nil {
			return err
		}
	}

	r := make([]frontend.Variable, claims.varsNum())

	// Just so that there is enough room for gJ to be reused
	maxDegree := claims.degree(0)
	for j := 1; j < claims.varsNum(); j++ {
		if d := claims.degree(j); d > maxDegree {
			maxDegree = d
		}
	}

	gJ := make(polynomial.Polynomial, maxDegree+1)   //At the end of iteration j, gJ = ∑_{i < 2ⁿ⁻ʲ⁻¹} g(X₁, ..., Xⱼ₊₁, i...)		NOTE: n is shorthand for claims.varsNum()
	gJR := claims.combinedSum(api, combinationCoeff) // At the beginning of iteration j, gJR = ∑_{i < 2ⁿ⁻ʲ} g(r₁, ..., rⱼ, i...)

	for j := 0; j < claims.varsNum(); j++ {
		partialSumPoly := proof.PartialSumPolys[j] //proof.PartialSumPolys(j)
		if len(partialSumPoly) != claims.degree(j) {
			return errors.New("malformed proof") //Malformed proof
		}
		copy(gJ[1:], partialSumPoly)
		gJ[0] = api.Sub(gJR, partialSumPoly[0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)
		// gJ is ready

		//Prepare for the next iteration
		if r[j], err = next(transcript, proof.PartialSumPolys[j], &remainingChallengeNames); err != nil {
			return err
		}

		gJR = polynomial.InterpolateLDE(api, r[j], gJ[:(claims.degree(j)+1)])
	}

	return claims.verifyFinalEval(api, r, combinationCoeff, gJR, proof.FinalEvalProof)

}
