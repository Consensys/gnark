package sumcheck

import (
	"fmt"
	"strconv"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
)

type config struct {
	prefix string
}

// Option allows to alter the sumcheck verifier behaviour.
type Option func(c *config) error

func (v *Verifier[FR]) setupTranscript(claimsNum int, varsNum int, settings *fiatshamir.SettingsFr[FR]) ([]string, error) {
	var fr FR
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
		settings.Transcript, err = recursion.NewTranscript(v.api, fr.Modulus(), challengeNames) // not passing settings.hash check
		if err != nil {
			return nil, err
		}
	}

	return challengeNames, v.bindChallenge(settings.Transcript, challengeNames[0], settings.BaseChallenges)
}

func (v *Verifier[FR]) next(transcript *fiatshamir.Transcript, bindings []emulated.Element[FR], remainingChallengeNames *[]string) (emulated.Element[FR], error) {
	challenge, newRemainingChallengeNames, err := v.deriveChallenge(transcript, *remainingChallengeNames, bindings)
	*remainingChallengeNames = newRemainingChallengeNames
	return *challenge, err
}

// WithClaimPrefix prepends the given string to the challenge names when
// computing the challenges inside the sumcheck verifier. The option is used in
// a higher level protocols to ensure that sumcheck claims are not interchanged.
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

// VerifyOption allows to alter the behaviour of the single sumcheck proof verification.
type VerifyOption[FR emulated.FieldParams] func(c *verifyCfg[FR]) error

// WithBaseChallenges allows to bind to additional baseChallenges (in addition
// to the current sumcheck protocol transcript) when computing the challenges.
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

// Verifier allows to check sumcheck proofs. See [NewVerifier] for initializing the instance.
type Verifier[FR emulated.FieldParams] struct {
	api frontend.API
	f   *emulated.Field[FR]
	p   *polynomial.Polynomial[FR]
	*config
}

// NewVerifier initializes a new sumcheck verifier for the parametric emulated
// field FR. It returns an error if the given options are invalid or when
// initializing emulated arithmetic fails.
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

// Verify verifies the sumcheck proof for the given (lazy) claims.
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

	combinationCoef := v.f.Zero()
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

// VerifyForGkr verifies the sumcheck proof for the given (lazy) claims.
func (v *Verifier[FR]) VerifyForGkr(claims LazyClaimsVar[FR], proof nonNativeProofGKR[FR], transcriptSettings fiatshamir.SettingsFr[FR]) error {

	remainingChallengeNames, err := v.setupTranscript(claims.NbClaims(), claims.NbVars(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return err
	}

	var combinationCoef emulated.Element[FR]

	if claims.NbClaims() >= 2 {
		if combinationCoef, err = v.next(transcript, []emulated.Element[FR]{}, &remainingChallengeNames); err != nil {
			return err
		}
	}

	r := make([]emulated.Element[FR], claims.NbVars())

	// Just so that there is enough room for gJ to be reused
	maxDegree := claims.Degree(0)
	for j := 1; j < claims.NbVars(); j++ {
		if d := claims.Degree(j); d > maxDegree {
			maxDegree = d
		}
	}

	gJ := make([]*emulated.Element[FR], maxDegree+1)   //At the end of iteration j, gJ = ∑_{i < 2ⁿ⁻ʲ⁻¹} g(X₁, ..., Xⱼ₊₁, i...)		NOTE: n is shorthand for claims.VarsNum()
	// gJR is the claimed value. In case of multiple claims it is combined
	// claimed value we're going to check against.
	gJR := claims.CombinedSum(&combinationCoef)

	for j := 0; j < claims.NbVars(); j++ {
		partialSumPoly := proof.PartialSumPolys[j] //proof.PartialSumPolys(j)
		if len(partialSumPoly) != claims.Degree(j) {
			return fmt.Errorf("malformed proof") //Malformed proof
		}
		copy(polynomial.FromSliceReferences(gJ[1:]), partialSumPoly)
		gJ[0] = v.f.Sub(gJR, &partialSumPoly[0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)
		// gJ is ready

		//Prepare for the next iteration
		if r[j], err = v.next(transcript, proof.PartialSumPolys[j], &remainingChallengeNames); err != nil {
			return err
		}

		gJR = v.p.InterpolateLDE(&r[j], gJ[:(claims.Degree(j)+1)])
	}

	return claims.VerifyFinalEval(r, combinationCoef, *gJR, proof.FinalEvalProof)
}