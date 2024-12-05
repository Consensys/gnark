package solidity

import (
	"fmt"
	"hash"

	"github.com/consensys/gnark/backend"
	"golang.org/x/crypto/sha3"
)

// ExportOption defines option for altering the behavior of the prover in
// Prove, ReadAndProve and IsSolved methods. See the descriptions of functions
// returning instances of this type for implemented options.
type ExportOption func(*ExportConfig) error

// ExportConfig is the configuration for the prover with the options applied.
type ExportConfig struct {
	PragmaVersion string
	HashToFieldFn hash.Hash
}

// NewExportConfig returns a default ExportConfig with given export options opts
// applied.
func NewExportConfig(opts ...ExportOption) (ExportConfig, error) {
	config := ExportConfig{
		// we set default pragma version to 0.8.0+ to avoid needing to sync Solidity CI all the time
		PragmaVersion: "^0.8.0",
	}
	for _, option := range opts {
		if err := option(&config); err != nil {
			return ExportConfig{}, err
		}
	}
	return config, nil
}

// WithPragmaVersion changes the pragma version used in the solidity verifier.
func WithPragmaVersion(version string) ExportOption {
	return func(cfg *ExportConfig) error {
		cfg.PragmaVersion = version
		return nil
	}
}

// WithHashToFieldFunction changes the hash function used for hashing
// bytes to field. If not set then the default hash function based on RFC 9380
// is used. Used mainly for compatibility between different systems and
// efficient recursion.
func WithHashToFieldFunction(hFunc hash.Hash) ExportOption {
	return func(cfg *ExportConfig) error {
		cfg.HashToFieldFn = hFunc
		return nil
	}
}

// WithProverTargetSolidityVerifier returns a prover option that sets all the
// necessary prover options which are suitable for verifying the proofs in the
// Solidity verifier.
//
// For PLONK this is a no-op option as the Solidity verifier is directly
// compatible with the default prover options. Regardless, it is recommended to
// use this option for consistency and possible future changes in the Solidity
// verifier.
//
// For Groth16 this option sets the hash function used for hashing bytes to
// field to [sha3.NewLegacyKeccak256] as the Solidity verifier does not support
// the standard hash-to-field function. We use legacy Keccak256 in Solidity for
// the cheapest gas usage.
func WithProverTargetSolidityVerifier(bid backend.ID) backend.ProverOption {
	switch bid {
	case backend.GROTH16:
		// Solidity verifier does not support standard hash-to-field function.
		// Choose efficient one.
		return backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256())
	case backend.PLONK:
		// default hash function works for PLONK. We just have to return a no-op option
		return func(*backend.ProverConfig) error {
			return nil
		}
	default:
		return func(*backend.ProverConfig) error {
			return fmt.Errorf("unsupported backend ID: %s", bid)
		}
	}
}

// WithVerifierTargetSolidityVerifier returns a verifier option that sets all
// the necessary verifier options which are suitable for verifying the proofs
// targeted for the Solidity verifier. See the comments in
// [WithProverTargetSolidityVerifier].
func WithVerifierTargetSolidityVerifier(bid backend.ID) backend.VerifierOption {
	switch bid {
	case backend.GROTH16:
		// Solidity verifier does not support standard hash-to-field function.
		// Choose efficient one.
		return backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256())
	case backend.PLONK:
		// default hash function works for PLONK. We just have to return a no-op option
		return func(*backend.VerifierConfig) error {
			return nil
		}
	default:
		return func(*backend.VerifierConfig) error {
			return fmt.Errorf("unsupported backend ID: %s", bid)
		}
	}
}
