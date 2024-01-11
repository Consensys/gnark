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
	baseChallenges []*emulated.Element[FR]
}

type VerifyOption[FR emulated.FieldParams] func(c *verifyCfg[FR]) error

// TODO: make parametric and then use emulated.Element as input?
func WithBaseChallenges[FR emulated.FieldParams](baseChallenges []*emulated.Element[FR]) VerifyOption[FR] {
	return func(c *verifyCfg[FR]) error {
		c.baseChallenges = append(c.baseChallenges, baseChallenges...)
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

func (v *Verifier[FR]) getChallengeNames(nbClaims int, nbVars int) []string {
	var challengeNames []string
	if nbClaims > 1 {
		challengeNames = []string{v.prefix + "comb"}
	}
	for i := 0; i < nbVars; i++ {
		challengeNames = append(challengeNames, fmt.Sprintf("%spSP.%d", v.prefix, i))
	}
	return challengeNames
}

func (v *Verifier[FR]) Verify(claims LazyClaims[FR], proof Proof[FR], opts ...VerifyOption[FR]) error {
	var fr FR
	cfg, err := newVerificationConfig(opts...)
	if err != nil {
		return fmt.Errorf("verification opts: %w", err)
	}
	challengeNames := v.getChallengeNames(claims.NbClaims(), claims.NbVars())
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
	r := make([]*emulated.Element[FR], claims.NbVars())

	gJR := claims.CombinedSum(combinationCoef)

	for j := 0; j < claims.NbVars(); j++ {
		partialSumPoly := proof.PartialSumPolys[j]
		degree := claims.Degree(j)
		if len(partialSumPoly) != degree {
			return fmt.Errorf("expected len %d, got %d", degree, len(partialSumPoly))
		}
		gj0 := v.f.Sub(gJR, partialSumPoly[0])
		gJ := polynomial.Univariate[FR]{gj0}
		gJ = append(gJ, partialSumPoly...)
		if r[j], challengeNames, err = v.deriveChallenge(fs, challengeNames, partialSumPoly); err != nil {
			return fmt.Errorf("round %d derive challenge: %w", j, err)
		}
		gJR = v.p.InterpolateLDE(r[j], gJ)
	}
	if err := claims.AssertEvaluation(r, combinationCoef, gJR, proof.FinalEvalProof); err != nil {
		return fmt.Errorf("assert final evaluation: %w", err)
	}

	return nil
}

func (v *Verifier[FR]) bindChallenge(fs *fiatshamir.Transcript, challengeName string, values []*emulated.Element[FR]) error {
	for i := range values {
		bts := v.f.ToBits(values[i])
		if err := fs.Bind(challengeName, bts); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

func (v *Verifier[FR]) deriveChallenge(fs *fiatshamir.Transcript, challengeNames []string, values []*emulated.Element[FR]) (challenge *emulated.Element[FR], restChallengeNames []string, err error) {
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
