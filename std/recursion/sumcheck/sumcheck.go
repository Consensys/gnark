package sumcheck

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
)

type config struct {
	prefix string
}

type Option func(c *config) error

func WithClaimPrefix(prefix string) Option {
	return func(c *config) error {
		c.prefix = prefix
		return nil
	}
}

func newConfig(opts ...Option) (*config, error) {
	cfg := new(config)
	for i := range opts {
		if err := opts[i](cfg); err != nil {
			return nil, fmt.Errorf("apply option %d: %w", i, err)
		}
	}
	return cfg, nil
}

type verifyCfg[FR emulated.FieldParams] struct {
	baseChallenges []emulated.Element[FR]
}

type VerifyOption[FR emulated.FieldParams] func(c *verifyCfg[FR]) error

func WithBaseChallenges[FR emulated.FieldParams](baseChallenges []*emulated.Element[FR]) VerifyOption[FR] {
	return func(c *verifyCfg[FR]) error {
		for i := range baseChallenges {
			c.baseChallenges = append(c.baseChallenges, *baseChallenges[i])
		}
		return nil
	}
}

func newVerificationConfig[FR emulated.FieldParams](opts ...VerifyOption[FR]) (*verifyCfg[FR], error) {
	cfg := new(verifyCfg[FR])
	for i := range opts {
		if err := opts[i](cfg); err != nil {
			return nil, fmt.Errorf("apply option %d: %w", i, err)
		}
	}
	return cfg, nil
}

type Verifier[FR emulated.FieldParams] struct {
	api frontend.API
	f   *emulated.Field[FR]
	p   *polynomial.Polynomial[FR]
	*config
}

func NewVerifier[FR emulated.FieldParams](api frontend.API, opts ...Option) (*Verifier[FR], error) {
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new configuration: %w", err)
	}
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	return &Verifier[FR]{
		api:    api,
		f:      f,
		p:      p,
		config: cfg,
	}, nil
}

func (v *Verifier[FR]) Verify(claims LazyClaims[FR], proof Proof[FR], opts ...VerifyOption[FR]) error {
	var fr FR
	cfg, err := newVerificationConfig(opts...)
	if err != nil {
		return fmt.Errorf("verification opts: %w", err)
	}
	challengeNames := getChallengeNames(v.prefix, claims.NbClaims(), claims.NbVars())
	fs, err := recursion.NewTranscript(v.api, fr.Modulus(), challengeNames)
	if err != nil {
		return fmt.Errorf("new transcript: %w", err)
	}
	// bind challenge from previous round if it is a continuation
	if err = v.bindChallenge(fs, challengeNames[0], cfg.baseChallenges); err != nil {
		return fmt.Errorf("base: %w", err)
	}

	var combinationCoef *emulated.Element[FR]
	if claims.NbClaims() >= 2 {
		if combinationCoef, challengeNames, err = v.deriveChallenge(fs, challengeNames, nil); err != nil {
			return fmt.Errorf("derive combination coef: %w", err)
		}
	}
	challenges := make([]*emulated.Element[FR], claims.NbVars())

	// gJR is the claimed value. In case of multiple claims it is combined
	// claimed value we're going to check against.
	gJR := claims.CombinedSum(combinationCoef)

	// sumcheck rounds
	for j := 0; j < claims.NbVars(); j++ {
		// instead of sending the polynomials themselves, the provers sends n evaluations of the round polynomial:
		//
		//   g_j(X_j) = \sum_{x_{j+1},...\x_k \in {0,1}} g(r_1, ..., r_{j-1}, X_j, x_{j+1}, ...)
		//
		// We already know g_{j-1}(r_{j-1}) from the previous rounds and use the assertion
		//
		//   g_j(0) + g_j(1) = g_{j-1}(r)
		//
		// to get another valid evaluation.
		evals := proof.RoundPolyEvaluations[j]
		degree := claims.Degree(j)
		if len(evals) != degree {
			return fmt.Errorf("expected len %d, got %d", degree, len(evals))
		}
		// computes g_{j-1}(r) - g_j(1) as missing evaluation
		gj0 := v.f.Sub(gJR, &evals[0])
		// construct the n+1 evaluations for interpolation
		gJ := []*emulated.Element[FR]{gj0}
		for i := range evals {
			gJ = append(gJ, &evals[i])
		}

		// we derive the challenge from prover message.
		if challenges[j], challengeNames, err = v.deriveChallenge(fs, challengeNames, evals); err != nil {
			return fmt.Errorf("round %d derive challenge: %w", j, err)
		}
		// now, we need to evaluate the polynomial defined by evaluation values
		// `eval` at r[j] (the computed challenge for this round). Instead of
		// interpolating and then evaluating we are computing the value
		// directly.
		gJR = v.p.InterpolateLDE(challenges[j], gJ)

		// we do not directly need to check gJR now - as in the next round we
		// compute new evaluation point from gJR then the check is performed
		// implicitly.
	}

	// we have run all the sumcheck rounds. Now the last thing for the verifier
	// is to check that g(r_1, ..., r_k) is correct. However, depending on the
	// implementation, the verifier either:
	//   * checks directly (we have the function at it is simple)
	//   * returns the gJR to the caller which then checks it later separately (in GKR)
	//   * something else -- for example we use polynomial commitment opening.
	//
	// To cover all the cases, we call the AssertEvaluation method of the claim
	// which implements the exact logic.
	if err := claims.AssertEvaluation(challenges, combinationCoef, gJR, proof.FinalEvalProof); err != nil {
		return fmt.Errorf("assert final evaluation: %w", err)
	}

	return nil
}

func (v *Verifier[FR]) bindChallenge(fs *fiatshamir.Transcript, challengeName string, values []emulated.Element[FR]) error {
	for i := range values {
		bts := v.f.ToBits(&values[i])
		if err := fs.Bind(challengeName, bts); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

func (v *Verifier[FR]) deriveChallenge(fs *fiatshamir.Transcript, challengeNames []string, values []emulated.Element[FR]) (challenge *emulated.Element[FR], restChallengeNames []string, err error) {
	var fr FR
	if err = v.bindChallenge(fs, challengeNames[0], values); err != nil {
		return nil, nil, fmt.Errorf("bind: %w", err)
	}
	nativeChallenge, err := fs.ComputeChallenge(challengeNames[0])
	if err != nil {
		return nil, nil, fmt.Errorf("compute challenge %s: %w", challengeNames[0], err)
	}
	// TODO: when implementing better way (construct from limbs instead of bits) then change
	chBts := bits.ToBinary(v.api, nativeChallenge, bits.WithNbDigits(fr.Modulus().BitLen()))
	challenge = v.f.FromBits(chBts...)
	return challenge, challengeNames[1:], nil
}
