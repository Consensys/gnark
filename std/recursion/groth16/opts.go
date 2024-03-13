package groth16

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/recursion"
)

type verifierCfg struct {
	algopt             []algopts.AlgebraOption
	pedopt             []pedersen.VerifierOption
	forceSubgroupCheck bool
}

// VerifierOption allows to modify the behaviour of Groth16 verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithCompleteArithmetic returns a VerifierOption that forces complete arithmetic.
func WithCompleteArithmetic() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.algopt = append(cfg.algopt, algopts.WithCompleteArithmetic())
		return nil
	}
}

// WithSubgroupCheck returns a VerifierOption that forces subgroup checks.
func WithSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.pedopt = append(cfg.pedopt, pedersen.WithSubgroupCheck())
		cfg.forceSubgroupCheck = true
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

// GetNativeProverOptions returns Groth16 prover options for the native prover
// to initialize the configuration suitable for in-circuit verification.
func GetNativeProverOptions(outer, field *big.Int) backend.ProverOption {
	return func(pc *backend.ProverConfig) error {
		htfProverHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get hash to field: %w", err)
		}
		htfOpt := backend.WithProverHashToFieldFunction(htfProverHasher)
		if err = htfOpt(pc); err != nil {
			return fmt.Errorf("apply prover htf option: %w", err)
		}
		return nil

	}
}

// GetNativeVerifierOptions returns Groth16 verifier options to initialize the
// configuration to be compatible with in-circuit verification.
func GetNativeVerifierOptions(outer, field *big.Int) backend.VerifierOption {
	return func(vc *backend.VerifierConfig) error {
		htfVerifierHasher, err := recursion.NewShort(outer, field)
		if err != nil {
			return fmt.Errorf("get hash to field: %w", err)
		}
		htfOpt := backend.WithVerifierHashToFieldFunction(htfVerifierHasher)
		if err = htfOpt(vc); err != nil {
			return fmt.Errorf("apply verifier htf option: %w", err)
		}
		return nil
	}
}
