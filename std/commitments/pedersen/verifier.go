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
	G         G2El
	GSigmaNeg G2El // (-1/σ)[G] for toxic σ
}

// Verifier verifies the knowledge proofs for a Pedersen commitments
type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api     frontend.API
	pairing algebra.Pairing[G1El, G2El, GtEl]
}

// NewVerifier returns a new verifier for Pedersen commitments.
func NewVerifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) (*Verifier[FR, G1El, G2El, GtEl], error) {
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("get pairing: %w", err)
	}
	return &Verifier[FR, G1El, G2El, GtEl]{api: api, pairing: pairing}, nil
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
	isValid, err := v.IsCommitmentValid(commitment, knowledgeProof, vk, opts...)
	if err != nil {
		return err
	}
	v.api.AssertIsEqual(isValid, 1)
	return nil
}

// IsCommitmentValid returns a variable that is 1 if the commitment and
// knowledge proof are valid and 0 otherwise.
func (v *Verifier[FR, G1El, G2El, GtEl]) IsCommitmentValid(commitment Commitment[G1El], knowledgeProof KnowledgeProof[G1El], vk VerifyingKey[G2El], opts ...VerifierOption) (frontend.Variable, error) {
	cfg, err := newCfg(opts...)
	if err != nil {
		return 0, fmt.Errorf("apply options: %w", err)
	}

	isValid := frontend.Variable(1)
	if cfg.subgroupCheck {
		isValid = v.api.Mul(isValid, v.pairing.IsOnG1(&commitment.G1El))
		isValid = v.api.Mul(isValid, v.pairing.IsOnG1(&knowledgeProof.G1El))
	}

	res, err := v.pairing.Pair([]*G1El{&commitment.G1El, &knowledgeProof.G1El}, []*G2El{&vk.GSigmaNeg, &vk.G})
	if err != nil {
		return 0, fmt.Errorf("pairing: %w", err)
	}

	isValid = v.api.Mul(isValid, v.pairing.IsEqual(res, v.pairing.One()))
	return isValid, nil
}

// TODO: add asserting with switches between different keys
