package phase1

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/setup/utils"
)

func (c *Contribution) Verify(prev *Contribution) error {
	// Compute R for τ, α, β
	tauR := utils.GenR(c.PublicKeys.Tau.SG, c.PublicKeys.Tau.SXG, prev.Hash[:], 1)
	alphaR := utils.GenR(c.PublicKeys.Alpha.SG, c.PublicKeys.Alpha.SXG, prev.Hash[:], 2)
	betaR := utils.GenR(c.PublicKeys.Beta.SG, c.PublicKeys.Beta.SXG, prev.Hash[:], 3)

	// Check for knowledge of toxic parameters
	if !utils.SameRatio(c.PublicKeys.Tau.SG, c.PublicKeys.Tau.SXG, c.PublicKeys.Tau.XR, tauR) {
		return errors.New("couldn't verify public key of τ")
	}
	if !utils.SameRatio(c.PublicKeys.Alpha.SG, c.PublicKeys.Alpha.SXG, c.PublicKeys.Alpha.XR, alphaR) {
		return errors.New("couldn't verify public key of α")
	}
	if !utils.SameRatio(c.PublicKeys.Beta.SG, c.PublicKeys.Beta.SXG, c.PublicKeys.Beta.XR, betaR) {
		return errors.New("couldn't verify public key of β")
	}

	// Check for valid updates using previous parameters
	if !utils.SameRatio(c.Parameters.G1.Tau[1], prev.Parameters.G1.Tau[1], tauR, c.PublicKeys.Tau.XR) {
		return errors.New("couldn't verify that [τ]₁ is based on previous contribution")
	}
	if !utils.SameRatio(c.Parameters.G1.AlphaTau[0], prev.Parameters.G1.AlphaTau[0], alphaR, c.PublicKeys.Alpha.XR) {
		return errors.New("couldn't verify that [α]₁ is based on previous contribution")
	}
	if !utils.SameRatio(c.Parameters.G1.BetaTau[0], prev.Parameters.G1.BetaTau[0], betaR, c.PublicKeys.Beta.XR) {
		return errors.New("couldn't verify that [β]₁ is based on previous contribution")
	}
	if !utils.SameRatio(c.PublicKeys.Tau.SG, c.PublicKeys.Tau.SXG, c.Parameters.G2.Tau[1], prev.Parameters.G2.Tau[1]) {
		return errors.New("couldn't verify that [τ]₂ is based on previous contribution")
	}
	if !utils.SameRatio(c.PublicKeys.Beta.SG, c.PublicKeys.Beta.SXG, c.Parameters.G2.Beta, prev.Parameters.G2.Beta) {
		return errors.New("couldn't verify that [β]₂ is based on previous contribution")
	}

	// Check for valid updates using powers of τ
	_, _, g1, g2 := bn254.Generators()
	tauL1, tauL2 := utils.LinearCombinationG1(c.Parameters.G1.Tau)
	if !utils.SameRatio(tauL1, tauL2, c.Parameters.G2.Tau[1], g2) {
		return errors.New("couldn't verify valid powers of τ in G₁")
	}
	alphaL1, alphaL2 := utils.LinearCombinationG1(c.Parameters.G1.AlphaTau)
	if !utils.SameRatio(alphaL1, alphaL2, c.Parameters.G2.Tau[1], g2) {
		return errors.New("couldn't verify valid powers of α(τ) in G₁")
	}
	betaL1, betaL2 := utils.LinearCombinationG1(c.Parameters.G1.BetaTau)
	if !utils.SameRatio(betaL1, betaL2, c.Parameters.G2.Tau[1], g2) {
		return errors.New("couldn't verify valid powers of α(τ) in G₁")
	}
	tau2L1, tau2L2 := utils.LinearCombinationG2(c.Parameters.G2.Tau)
	if !utils.SameRatio(c.Parameters.G1.Tau[1], g1, tau2L1, tau2L2) {
		return errors.New("couldn't verify valid powers of τ in G₂")
	}

	// Check hash of the contribution
	h := HashContribution(c)
	for i := 0; i < len(h); i++ {
		if h[i] != c.Hash[i] {
			return errors.New("couldn't verify hash of contribution")
		}
	}

	return nil
}
