package phase2

import (
	"errors"

	"github.com/consensys/gnark/backend/groth16/setup/utils"
)

func (c *Contribution) Verify(prev *Contribution) error {
	// Compute R for δ
	deltaR := utils.GenR(c.PublicKey.SG, c.PublicKey.SXG, prev.Hash[:], 1)

	// Check for knowledge of δ
	if !utils.SameRatio(c.PublicKey.SG, c.PublicKey.SXG, c.PublicKey.XR, deltaR) {
		return errors.New("couldn't verify knowledge of δ")
	}

	// Check for valid updates using previous parameters
	if !utils.SameRatio(c.Parameters.G1.Delta, prev.Parameters.G1.Delta, deltaR, c.PublicKey.XR) {
		return errors.New("couldn't verify that [δ]₁ is based on previous contribution")
	}
	if !utils.SameRatio(c.PublicKey.SG, c.PublicKey.SXG, c.Parameters.G2.Delta, prev.Parameters.G2.Delta) {
		return errors.New("couldn't verify that [δ]₂ is based on previous contribution")
	}

	// Check for valid updates of L and Z using
	L, prevL := utils.Merge(c.Parameters.G1.L, prev.Parameters.G1.L)
	if !utils.SameRatio(L, prevL, c.Parameters.G2.Delta, prev.Parameters.G2.Delta) {
		return errors.New("couldn't verify valid updates of L using δ⁻¹")
	}
	Z, prevZ := utils.Merge(c.Parameters.G1.Z, prev.Parameters.G1.Z)
	if !utils.SameRatio(Z, prevZ, c.Parameters.G2.Delta, prev.Parameters.G2.Delta) {
		return errors.New("couldn't verify valid updates of L using δ⁻¹")
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
