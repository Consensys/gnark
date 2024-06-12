package sumcheck

import (
	"fmt"
	"math/big"
	"slices"
	"strconv"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/frontend"
	fiatshamirGnark "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/std/recursion"
)

type proverConfig struct {
	prefix         string
	baseChallenges []*big.Int
}

type proverOption func(*proverConfig) error

func withProverPrefix(prefix string) proverOption {
	return func(pc *proverConfig) error {
		pc.prefix = prefix
		return nil
	}
}

func newProverConfig(opts ...proverOption) (*proverConfig, error) {
	ret := new(proverConfig)
	for i := range opts {
		if err := opts[i](ret); err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}
	return ret, nil
}

func prove(current *big.Int, target *big.Int, claims claims, opts ...proverOption) (nativeProof, error) {
	var proof nativeProof
	cfg, err := newProverConfig(opts...)
	if err != nil {
		return proof, fmt.Errorf("parse options: %w", err)
	}
	challengeNames := getChallengeNames(cfg.prefix, claims.NbClaims(), claims.NbVars())
	fshash, err := recursion.NewShort(current, target)
	if err != nil {
		return proof, fmt.Errorf("new short hash: %w", err)
	}
	fs := fiatshamir.NewTranscript(fshash, challengeNames...)
	if err != nil {
		return proof, fmt.Errorf("new transcript: %w", err)
	}
	// bind challenge from previous round if it is a continuation
	if err = bindChallengeProver(fs, challengeNames[0], cfg.baseChallenges); err != nil {
		return proof, fmt.Errorf("base: %w", err)
	}

	combinationCoef := big.NewInt(0)
	if claims.NbClaims() >= 2 {
		if combinationCoef, challengeNames, err = deriveChallengeProver(fs, challengeNames, nil); err != nil {
			return proof, fmt.Errorf("derive combination coef: %w", err)
		}
	}
	// in sumcheck we run a round for every variable. So the number of variables
	// defines the number of rounds.
	nbVars := claims.NbVars()
	proof.RoundPolyEvaluations = make([]nativePolynomial, nbVars)
	// the first round in the sumcheck is without verifier challenge. Combine challenges and provers sends the first polynomial
	proof.RoundPolyEvaluations[0] = claims.Combine(combinationCoef)

	challenges := make([]*big.Int, nbVars)

	// we iterate over all variables. However, we omit the last round as the
	// final evaluation is possibly deferred.
	for j := 0; j < nbVars-1; j++ {
		// compute challenge for the next round
		if challenges[j], challengeNames, err = deriveChallengeProver(fs, challengeNames, proof.RoundPolyEvaluations[j]); err != nil {
			return proof, fmt.Errorf("derive challenge: %w", err)
		}
		// compute the univariate polynomial with first j variables fixed.
		proof.RoundPolyEvaluations[j+1] = claims.Next(challenges[j])

	}
	if challenges[nbVars-1], challengeNames, err = deriveChallengeProver(fs, challengeNames, proof.RoundPolyEvaluations[nbVars-1]); err != nil {
		return proof, fmt.Errorf("derive challenge: %w", err)
	}
	if len(challengeNames) > 0 {
		return proof, fmt.Errorf("excessive challenges")
	}
	proof.FinalEvalProof = claims.ProverFinalEval(challenges)

	return proof, nil
}

// todo change this bind as limbs instead of bits, ask @arya if necessary
// bindChallenge binds the values for challengeName using in-circuit Fiat-Shamir transcript.
func bindChallenge(api frontend.API, targetModulus *big.Int, fs *fiatshamirGnark.Transcript, challengeName string, values []frontend.Variable) error {
	for i := range values {
		bts := bits.ToBinary(api, values[i], bits.WithNbDigits(targetModulus.BitLen()))
		slices.Reverse(bts)
		if err := fs.Bind(challengeName, bts); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

func setupTranscript(api frontend.API, targetModulus *big.Int, claimsNum int, varsNum int, settings *fiatshamirGnark.Settings) ([]string, error) {

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
	// todo check if settings.Transcript is nil
	if settings.Transcript == nil {
		var err error
		settings.Transcript, err = recursion.NewTranscript(api, targetModulus, challengeNames) // not passing settings.hash check
		if err != nil {
			return nil, err
		}
	}

	return challengeNames, bindChallenge(api, targetModulus, settings.Transcript, challengeNames[0], settings.BaseChallenges)
}

func next(transcript *fiatshamirGnark.Transcript, bindings []frontend.Variable, remainingChallengeNames *[]string) (frontend.Variable, error) {
	challengeName := (*remainingChallengeNames)[0]
	if err := transcript.Bind(challengeName, bindings); err != nil {
		return nil, err
	}

	res, err := transcript.ComputeChallenge(challengeName)
	*remainingChallengeNames = (*remainingChallengeNames)[1:]
	return res, err
}

// Prove create a non-interactive sumcheck proof
func SumcheckProve(api frontend.API, targetModulus *big.Int, claims claimsVar, transcriptSettings fiatshamirGnark.Settings) (nativeProofGKR, error) {

	var proof nativeProofGKR
	remainingChallengeNames, err := setupTranscript(api, targetModulus, claims.NbClaims(), claims.NbVars(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return proof, err
	}

	var combinationCoeff frontend.Variable
	if claims.NbClaims() >= 2 {
		if combinationCoeff, err = next(transcript, []frontend.Variable{}, &remainingChallengeNames); err != nil {
			return proof, err
		}
	}

	varsNum := claims.NbVars()
	proof.PartialSumPolys = make([]polynomial.Polynomial, varsNum)
	proof.PartialSumPolys[0] = claims.Combine(api, &combinationCoeff)
	challenges := make([]frontend.Variable, varsNum)

	for j := 0; j+1 < varsNum; j++ {
		if challenges[j], err = next(transcript, proof.PartialSumPolys[j], &remainingChallengeNames); err != nil {
			return proof, err
		}
		proof.PartialSumPolys[j+1] = claims.Next(api, &challenges[j])
	}

	if challenges[varsNum-1], err = next(transcript, proof.PartialSumPolys[varsNum-1], &remainingChallengeNames); err != nil {
		return proof, err
	}

	proof.FinalEvalProof = claims.ProverFinalEval(api, challenges)

	return proof, nil
}