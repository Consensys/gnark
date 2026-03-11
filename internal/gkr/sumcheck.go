package gkr

import (
	"errors"
	"strconv"

	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
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

func setupTranscript(api frontend.API, varsNum int, settings *fiatshamir.Settings) ([]string, error) {
	challengeNames := make([]string, varsNum)
	prefix := settings.Prefix + "pSP."
	for i := 0; i < varsNum; i++ {
		challengeNames[i] = prefix + strconv.Itoa(i)
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

func verifySumcheck(api frontend.API, claims sumcheckLazyClaims, proof sumcheckProof, claimedSum frontend.Variable, degree int, transcriptSettings fiatshamir.Settings) error {

	remainingChallengeNames, err := setupTranscript(api, claims.varsNum(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return err
	}

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

		if r[j], err = next(transcript, proof.PartialSumPolys[j], &remainingChallengeNames); err != nil {
			return err
		}

		gJR = polynomial.InterpolateLDE(api, r[j], gJ[:(degree+1)])
	}

	return claims.verifyFinalEval(api, r, gJR, proof.FinalEvalProof)

}
