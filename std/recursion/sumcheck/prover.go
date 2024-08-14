package sumcheck

import (
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/std/recursion"
)

type proverConfig struct {
	prefix         string
	baseChallenges []*big.Int
}

type proverOption func(*proverConfig) error

func newProverConfig(opts ...proverOption) (*proverConfig, error) {
	ret := new(proverConfig)
	for i := range opts {
		if err := opts[i](ret); err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}
	return ret, nil
}

func Prove(current *big.Int, target *big.Int, claims claims, opts ...proverOption) (NativeProof, error) {
	var proof NativeProof
	cfg, err := newProverConfig(opts...)
	if err != nil {
		return proof, fmt.Errorf("parse options: %w", err)
	}
	challengeNames := getChallengeNames(cfg.prefix, 1, claims.NbVars()) // claims.NbClaims()
	fshash, err := recursion.NewShort(current, target)
	if err != nil {
		return proof, fmt.Errorf("new short hash: %w", err)
	}
	fs := fiatshamir.NewTranscript(fshash, challengeNames...)
	// bind challenge from previous round if it is a continuation
	if err = BindChallengeProver(fs, challengeNames[0], cfg.baseChallenges); err != nil {
		return proof, fmt.Errorf("base: %w", err)
	}

	combinationCoef := big.NewInt(0)
	// if claims.NbClaims() >= 2 { // todo change this to handle multiple claims per wire - assuming single claim per wire so don't need to combine
	// 	if combinationCoef, challengeNames, err = DeriveChallengeProver(fs, challengeNames, nil); err != nil {
	// 		return proof, fmt.Errorf("derive combination coef: %w", err)
	// 	} // todo change this nbclaims give 6 results in combination coeff
	// }

	// in sumcheck we run a round for every variable. So the number of variables
	// defines the number of rounds.
	nbVars := claims.NbVars()
	proof.RoundPolyEvaluations = make([]NativePolynomial, nbVars)
	// the first round in the sumcheck is without verifier challenge. Combine challenges and provers sends the first polynomial
	proof.RoundPolyEvaluations[0] = claims.Combine(combinationCoef)
	challenges := make([]*big.Int, nbVars)

	// we iterate over all variables. However, we omit the last round as the
	// final evaluation is possibly deferred.
	for j := 0; j < nbVars-1; j++ {
		// compute challenge for the next round
		if challenges[j], challengeNames, err = DeriveChallengeProver(fs, challengeNames, proof.RoundPolyEvaluations[j]); err != nil {
			return proof, fmt.Errorf("derive challenge: %w", err)
		}
		// compute the univariate polynomial with first j variables fixed.
		proof.RoundPolyEvaluations[j+1] = claims.Next(challenges[j])


	}
	if challenges[nbVars-1], challengeNames, err = DeriveChallengeProver(fs, challengeNames, proof.RoundPolyEvaluations[nbVars-1]); err != nil {
		return proof, fmt.Errorf("derive challenge: %w", err)
	}
	if len(challengeNames) > 0 {
		return proof, fmt.Errorf("excessive challenges")
	}

	proof.FinalEvalProof = claims.ProverFinalEval(challenges)

	return proof, nil
}
