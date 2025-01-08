package sumcheck

import (
	"fmt"
	"strconv"

	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
)

// LazyClaims is the Claims data structure on the verifier side. It is "lazy" in that it has to compute fewer things.
type LazyClaims interface {
	ClaimsNum() int                                                      // ClaimsNum = m
	VarsNum() int                                                        // VarsNum = n
	CombinedSum(api frontend.API, a frontend.Variable) frontend.Variable // CombinedSum returns c = ∑_{1≤j≤m} aʲ⁻¹cⱼ
	Degree(i int) int                                                    //Degree of the total claim in the i'th variable
	VerifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff, purportedValue frontend.Variable, proof interface{}) error
}

// Proof of a multi-sumcheck statement.
type Proof struct {
	PartialSumPolys []polynomial.Polynomial
	FinalEvalProof  interface{}
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

func Verify(api frontend.API, claims LazyClaims, proof Proof, transcriptSettings fiatshamir.Settings) error {

	remainingChallengeNames, err := setupTranscript(api, claims.ClaimsNum(), claims.VarsNum(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return err
	}

	var combinationCoeff frontend.Variable

	if claims.ClaimsNum() >= 2 {
		if combinationCoeff, err = next(transcript, []frontend.Variable{}, &remainingChallengeNames); err != nil {
			return err
		}
	}

	r := make([]frontend.Variable, claims.VarsNum())

	// Just so that there is enough room for gJ to be reused
	maxDegree := claims.Degree(0)
	for j := 1; j < claims.VarsNum(); j++ {
		if d := claims.Degree(j); d > maxDegree {
			maxDegree = d
		}
	}

	gJ := make(polynomial.Polynomial, maxDegree+1)   //At the end of iteration j, gJ = ∑_{i < 2ⁿ⁻ʲ⁻¹} g(X₁, ..., Xⱼ₊₁, i...)		NOTE: n is shorthand for claims.VarsNum()
	gJR := claims.CombinedSum(api, combinationCoeff) // At the beginning of iteration j, gJR = ∑_{i < 2ⁿ⁻ʲ} g(r₁, ..., rⱼ, i...)

	for j := 0; j < claims.VarsNum(); j++ {
		partialSumPoly := proof.PartialSumPolys[j] //proof.PartialSumPolys(j)
		if len(partialSumPoly) != claims.Degree(j) {
			return fmt.Errorf("malformed proof") //Malformed proof
		}
		copy(gJ[1:], partialSumPoly)
		gJ[0] = api.Sub(gJR, partialSumPoly[0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)
		// gJ is ready

		//Prepare for the next iteration
		if r[j], err = next(transcript, proof.PartialSumPolys[j], &remainingChallengeNames); err != nil {
			return err
		}

		gJR = polynomial.InterpolateLDE(api, r[j], gJ[:(claims.Degree(j)+1)])
	}

	return claims.VerifyFinalEval(api, r, combinationCoeff, gJR, proof.FinalEvalProof)

}
