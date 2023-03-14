package setup

import (
	"crypto/sha256"
	"errors"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16/setup/utils"
)

// Phase1 represents the Phase1 of the MPC described in
// https://eprint.iacr.org/2017/1050.pdf
//
// Also known as "Powers of Tau"
type Phase1 struct {
	Parameters struct {
		G1 struct {
			Tau      []bn254.G1Affine // {[τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ⁿ⁻²]₁}
			AlphaTau []bn254.G1Affine // {α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τⁿ⁻¹]₁}
			BetaTau  []bn254.G1Affine // {β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τⁿ⁻¹]₁}
		}
		G2 struct {
			Tau  []bn254.G2Affine // {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τⁿ⁻¹]₂}
			Beta bn254.G2Affine   // [β]₂
		}
	}
	PublicKeys struct {
		Tau, Alpha, Beta utils.PublicKey
	}
	Hash []byte // sha256 hash
}

// InitPhase1 initialize phase 1 of the MPC. This is called once by the coordinator before
// any randomness contribution is made (see Contribute()).
func InitPhase1(power int) (phase1 Phase1) {
	N := int(math.Pow(2, float64(power)))

	// Generate key pairs
	var tau, alpha, beta fr.Element
	tau.SetOne()
	alpha.SetOne()
	beta.SetOne()
	phase1.PublicKeys.Tau = utils.GenPublicKey(tau, nil, 1)
	phase1.PublicKeys.Alpha = utils.GenPublicKey(alpha, nil, 2)
	phase1.PublicKeys.Beta = utils.GenPublicKey(beta, nil, 3)

	// First contribution use generators
	_, _, g1, g2 := bn254.Generators()
	phase1.Parameters.G2.Beta.Set(&g2)
	phase1.Parameters.G1.Tau = make([]bn254.G1Affine, 2*N-1)
	phase1.Parameters.G2.Tau = make([]bn254.G2Affine, N)
	phase1.Parameters.G1.AlphaTau = make([]bn254.G1Affine, N)
	phase1.Parameters.G1.BetaTau = make([]bn254.G1Affine, N)
	for i := 0; i < len(phase1.Parameters.G1.Tau); i++ {
		phase1.Parameters.G1.Tau[i].Set(&g1)
	}
	for i := 0; i < len(phase1.Parameters.G2.Tau); i++ {
		phase1.Parameters.G2.Tau[i].Set(&g2)
		phase1.Parameters.G1.AlphaTau[i].Set(&g1)
		phase1.Parameters.G1.BetaTau[i].Set(&g1)
	}

	phase1.Parameters.G2.Beta.Set(&g2)

	// Compute hash of Contribution
	phase1.Hash = phase1.hash()

	return
}

// Contribute contributes randomness to the phase1 object. This mutates phase1.
func (phase1 *Phase1) Contribute() {
	N := len(phase1.Parameters.G2.Tau)

	// Generate key pairs
	var tau, alpha, beta fr.Element
	tau.SetRandom()
	alpha.SetRandom()
	beta.SetRandom()
	phase1.PublicKeys.Tau = utils.GenPublicKey(tau, phase1.Hash[:], 1)
	phase1.PublicKeys.Alpha = utils.GenPublicKey(alpha, phase1.Hash[:], 2)
	phase1.PublicKeys.Beta = utils.GenPublicKey(beta, phase1.Hash[:], 3)

	// Compute powers of τ, ατ, and βτ
	taus := utils.Powers(tau, 2*N-1)
	alphaTau := make([]fr.Element, N)
	betaTau := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		alphaTau[i].Mul(&taus[i], &alpha)
		betaTau[i].Mul(&taus[i], &beta)
	}

	// Update using previous parameters
	phase1.Parameters.G1.Tau = utils.ScaleG1(phase1.Parameters.G1.Tau, taus)
	phase1.Parameters.G2.Tau = utils.ScaleG2(phase1.Parameters.G2.Tau, taus[0:N])
	phase1.Parameters.G1.AlphaTau = utils.ScaleG1(phase1.Parameters.G1.AlphaTau, alphaTau)
	phase1.Parameters.G1.BetaTau = utils.ScaleG1(phase1.Parameters.G1.BetaTau, betaTau)
	var betaBI big.Int
	beta.BigInt(&betaBI)
	phase1.Parameters.G2.Beta.ScalarMultiplication(&phase1.Parameters.G2.Beta, &betaBI)

	// Compute hash of Contribution
	phase1.Hash = phase1.hash()
}

func VerifyPhase1(c0, c1 *Phase1, c ...*Phase1) error {
	contribs := append([]*Phase1{c0, c1}, c...)
	for i := 0; i < len(contribs)-1; i++ {
		if err := verifyPhase1(contribs[i], contribs[i+1]); err != nil {
			return err
		}
	}
	return nil
}

// verifyPhase1 checks that a contribution is based on a known previous Phase1 state.
func verifyPhase1(current, contribution *Phase1) error {
	// Compute R for τ, α, β
	tauR := utils.GenR(contribution.PublicKeys.Tau.SG, contribution.PublicKeys.Tau.SXG, current.Hash[:], 1)
	alphaR := utils.GenR(contribution.PublicKeys.Alpha.SG, contribution.PublicKeys.Alpha.SXG, current.Hash[:], 2)
	betaR := utils.GenR(contribution.PublicKeys.Beta.SG, contribution.PublicKeys.Beta.SXG, current.Hash[:], 3)

	// Check for knowledge of toxic parameters
	if !utils.SameRatio(contribution.PublicKeys.Tau.SG, contribution.PublicKeys.Tau.SXG, contribution.PublicKeys.Tau.XR, tauR) {
		return errors.New("couldn't verify public key of τ")
	}
	if !utils.SameRatio(contribution.PublicKeys.Alpha.SG, contribution.PublicKeys.Alpha.SXG, contribution.PublicKeys.Alpha.XR, alphaR) {
		return errors.New("couldn't verify public key of α")
	}
	if !utils.SameRatio(contribution.PublicKeys.Beta.SG, contribution.PublicKeys.Beta.SXG, contribution.PublicKeys.Beta.XR, betaR) {
		return errors.New("couldn't verify public key of β")
	}

	// Check for valid updates using previous parameters
	if !utils.SameRatio(contribution.Parameters.G1.Tau[1], current.Parameters.G1.Tau[1], tauR, contribution.PublicKeys.Tau.XR) {
		return errors.New("couldn't verify that [τ]₁ is based on previous contribution")
	}
	if !utils.SameRatio(contribution.Parameters.G1.AlphaTau[0], current.Parameters.G1.AlphaTau[0], alphaR, contribution.PublicKeys.Alpha.XR) {
		return errors.New("couldn't verify that [α]₁ is based on previous contribution")
	}
	if !utils.SameRatio(contribution.Parameters.G1.BetaTau[0], current.Parameters.G1.BetaTau[0], betaR, contribution.PublicKeys.Beta.XR) {
		return errors.New("couldn't verify that [β]₁ is based on previous contribution")
	}
	if !utils.SameRatio(contribution.PublicKeys.Tau.SG, contribution.PublicKeys.Tau.SXG, contribution.Parameters.G2.Tau[1], current.Parameters.G2.Tau[1]) {
		return errors.New("couldn't verify that [τ]₂ is based on previous contribution")
	}
	if !utils.SameRatio(contribution.PublicKeys.Beta.SG, contribution.PublicKeys.Beta.SXG, contribution.Parameters.G2.Beta, current.Parameters.G2.Beta) {
		return errors.New("couldn't verify that [β]₂ is based on previous contribution")
	}

	// Check for valid updates using powers of τ
	_, _, g1, g2 := bn254.Generators()
	tauL1, tauL2 := utils.LinearCombinationG1(contribution.Parameters.G1.Tau)
	if !utils.SameRatio(tauL1, tauL2, contribution.Parameters.G2.Tau[1], g2) {
		return errors.New("couldn't verify valid powers of τ in G₁")
	}
	alphaL1, alphaL2 := utils.LinearCombinationG1(contribution.Parameters.G1.AlphaTau)
	if !utils.SameRatio(alphaL1, alphaL2, contribution.Parameters.G2.Tau[1], g2) {
		return errors.New("couldn't verify valid powers of α(τ) in G₁")
	}
	betaL1, betaL2 := utils.LinearCombinationG1(contribution.Parameters.G1.BetaTau)
	if !utils.SameRatio(betaL1, betaL2, contribution.Parameters.G2.Tau[1], g2) {
		return errors.New("couldn't verify valid powers of α(τ) in G₁")
	}
	tau2L1, tau2L2 := utils.LinearCombinationG2(contribution.Parameters.G2.Tau)
	if !utils.SameRatio(contribution.Parameters.G1.Tau[1], g1, tau2L1, tau2L2) {
		return errors.New("couldn't verify valid powers of τ in G₂")
	}

	// Check hash of the contribution
	h := contribution.hash()
	for i := 0; i < len(h); i++ {
		if h[i] != contribution.Hash[i] {
			return errors.New("couldn't verify hash of contribution")
		}
	}

	return nil
}

func (phase1 *Phase1) hash() []byte {
	sha := sha256.New()
	phase1.writeTo(sha)
	return sha.Sum(nil)
}
