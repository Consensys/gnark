package groth16

import (
	"fmt"

	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/hash"
)

type verifierCfg struct {
	HashToFieldFn hash.FieldHasher
	algopt        []algopts.AlgebraOption
}

// VerifierOption allows to modify the behaviour of Groth16 verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithVerifierHashToFieldFn changes the hash function used for hashing
// bytes to field. If not set verifier will return an error when
// hashing is required.
func WithVerifierHashToFieldFn(h hash.FieldHasher) VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.HashToFieldFn = h
		return nil
	}
}

// WithCompleteArithmetic returns a VerifierOption that forces complete arithmetic.
func WithCompleteArithmetic() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.algopt = append(cfg.algopt, algopts.WithCompleteArithmetic())
		return nil
	}
}

func newCfg(opts ...VerifierOption) (*verifierCfg, error) {
	cfg := new(verifierCfg)
	for i := range opts {
		if err := opts[i](cfg); err != nil {
			return nil, fmt.Errorf("option %d: %w", i, err)
		}
	}
	return cfg, nil
}
