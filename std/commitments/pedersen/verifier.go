// Package pedersen implements the Pedersen vector commitment scheme verifier.
package pedersen

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
)

// Commitment is a Pedersen commitment to a vector.
type Commitment[G1El algebra.G1ElementT] struct {
	G1El G1El
}

// KnowledgeProof is a knowledge proof for a Pedersen commitment.
type KnowledgeProof[G1El algebra.G1ElementT] struct {
	G1El G1El
}

// VerifyingKey is a verifying key for Pedersen vector commitments.
type VerifyingKey[G2El algebra.G2ElementT] struct {
	G             G2El
	GRootSigmaNeg G2El // (-1/σ)[G] for toxic σ
}

// Verifier verifies the knowledge proofs for a Pedersen commitments
type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	pairing algebra.Pairing[G1El, G2El, GtEl]
}

// NewVerifier returns a new verifier for Pedersen commitments.
func NewVerifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) (*Verifier[FR, G1El, G2El, GtEl], error) {
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("get pairing: %w", err)
	}
	return &Verifier[FR, G1El, G2El, GtEl]{pairing: pairing}, nil
}

// FoldCommitments folds the given commitments into a single commitment for efficient verification.
//
// Currently the function panics as folding is not implemented yet.
func (v *Verifier[FR, G1El, G2El, GtEl]) FoldCommitments(commitments []Commitment[G1El], auxTranscript ...*emulated.Element[FR]) (Commitment[G1El], error) {
	if len(commitments) == 0 {
		return Commitment[G1El]{}, fmt.Errorf("number of commitments must be at least 1")
	}
	if len(commitments) == 1 { // no need to fold
		return commitments[0], nil
	}
	panic("folding not implemented yet")
}

// AssertCommitment verifies the given commitment and knowledge proof against the given verifying key.
func (v *Verifier[FR, G1El, G2El, GtEl]) AssertCommitment(commitment Commitment[G1El], knowledgeProof KnowledgeProof[G1El], vk VerifyingKey[G2El], opts ...VerifierOption) error {
	cfg, err := newCfg(opts...)
	if err != nil {
		return fmt.Errorf("apply options: %w", err)
	}
	if cfg.subgroupCheck {
		v.pairing.AssertIsOnG1(&commitment.G1El)
		v.pairing.AssertIsOnG1(&knowledgeProof.G1El)
	}

	v.pairing.PairingCheck([]*G1El{&commitment.G1El, &knowledgeProof.G1El}, []*G2El{&vk.G, &vk.GRootSigmaNeg})
	return nil
}

// TODO: add asserting with switches between different keys
