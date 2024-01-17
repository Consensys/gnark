package sumcheck

import (
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
)

type Proof[FR emulated.FieldParams] struct {
	// PartialSumPolys is polynomial representation in evaluation form
	RoundPolyEvaluations []polynomial.Univariate[FR]
	FinalEvalProof       EvaluationProof
}

func ValueOfProof[FR emulated.FieldParams](nproof NativeProof) Proof[FR] {
	rps := make([]polynomial.Univariate[FR], len(nproof.RoundPolyEvaluations))
	for i := range nproof.RoundPolyEvaluations {
		rps[i] = polynomial.ValueOfUnivariate[FR](nproof.RoundPolyEvaluations[i])
	}
	// TODO: type switch FinalEvalProof when it is not-nil
	return Proof[FR]{
		RoundPolyEvaluations: rps,
	}
}

func PlaceholderMultilinearProof[FR emulated.FieldParams](nbVars int) Proof[FR] {
	rps := make([]polynomial.Univariate[FR], nbVars)
	for i := range rps {
		rps[i] = polynomial.PlaceholderUnivariate[FR](1)
	}
	return Proof[FR]{
		RoundPolyEvaluations: rps,
	}
}

type EvaluationProof interface{}

type NativeProof struct {
	RoundPolyEvaluations [][]*big.Int
	FinalEvalProof       NativeEvaluationProof
}

type NativeEvaluationProof interface{}

type bigIntEngine struct {
	mod *big.Int
}

func (be *bigIntEngine) Add(dst, a, b *big.Int) *big.Int {
	dst.Add(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) Mul(dst, a, b *big.Int) *big.Int {
	dst.Mul(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

func (be *bigIntEngine) Sub(dst, a, b *big.Int) *big.Int {
	dst.Sub(a, b)
	dst.Mod(dst, be.mod)
	return dst
}

type proverConfig struct {
	prefix         string
	baseChallenges []*big.Int
}

type ProverOption func(*proverConfig) error

func WithProverPrefix(prefix string) ProverOption {
	return func(pc *proverConfig) error {
		pc.prefix = prefix
		return nil
	}
}

func newProverConfig(opts ...ProverOption) (*proverConfig, error) {
	ret := new(proverConfig)
	for i := range opts {
		if err := opts[i](ret); err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}
	return ret, nil
}

func Prove(current *big.Int, target *big.Int, claims Claims, opts ...ProverOption) (NativeProof, error) {
	var proof NativeProof
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
	if err = bindChallenge(fs, challengeNames[0], cfg.baseChallenges); err != nil {
		return proof, fmt.Errorf("base: %w", err)
	}

	var combinationCoef *big.Int
	if claims.NbClaims() >= 2 {
		if combinationCoef, challengeNames, err = deriveChallenge(fs, challengeNames, nil); err != nil {
			return proof, fmt.Errorf("derive combination coef: %w", err)
		}
	}
	// in sumcheck we run a round for every variable. So the number of variables
	// defines the number of rounds.
	nbVars := claims.NbVars()
	proof.RoundPolyEvaluations = make([][]*big.Int, nbVars)
	// the first round in the sumcheck is without verifier challenge. Combine challenges and provers sends the first polynomial
	proof.RoundPolyEvaluations[0] = claims.Combine(combinationCoef)

	challenges := make([]*big.Int, nbVars)

	// we iterate over all variables. However, we omit the last round as the
	// final evaluation is possibly deferred.
	for j := 0; j < nbVars-1; j++ {
		// compute challenge for the next round
		if challenges[j], challengeNames, err = deriveChallenge(fs, challengeNames, proof.RoundPolyEvaluations[j]); err != nil {
			return proof, fmt.Errorf("derive challenge: %w", err)
		}
		// compute the univariate polynomial with first j variables fixed.
		proof.RoundPolyEvaluations[j+1] = claims.ToUnivariate(challenges[j])

	}
	if challenges[nbVars-1], challengeNames, err = deriveChallenge(fs, challengeNames, proof.RoundPolyEvaluations[nbVars-1]); err != nil {
		return proof, fmt.Errorf("derive challenge: %w", err)
	}
	if len(challengeNames) > 0 {
		return proof, fmt.Errorf("excessive challenges")
	}
	proof.FinalEvalProof = claims.ProverFinalEval(challenges)

	return proof, nil
}

func bindChallenge(fs *fiatshamir.Transcript, challengeName string, values []*big.Int) error {
	var buf = make([]byte, 32)
	for i := range values {
		values[i].FillBytes(buf)
		if err := fs.Bind(challengeName, buf); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

func deriveChallenge(fs *fiatshamir.Transcript, challengeNames []string, values []*big.Int) (challenge *big.Int, restChallengeNames []string, err error) {
	if err = bindChallenge(fs, challengeNames[0], values); err != nil {
		return nil, nil, fmt.Errorf("bind: %w", err)
	}
	nativeChallenge, err := fs.ComputeChallenge(challengeNames[0])
	if err != nil {
		return nil, nil, fmt.Errorf("compute challenge %s: %w", challengeNames[0], err)
	}
	challenge = new(big.Int).SetBytes(nativeChallenge)
	return challenge, challengeNames[1:], nil
}
