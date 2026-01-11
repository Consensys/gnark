package solidity

import (
	"fmt"
	"hash"
	"io"
	"sort"

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
	// Imports contains additional import statements to include in the generated contract.
	// Each key is an import statement (without semicolon), sorted by key for deterministic output.
	Imports map[string]struct{}
	// Interfaces contains the interface names that the contract implements.
	Interfaces []string
	// Constants contains additional constant declarations to include in the contract.
	Constants string
	// Constructor contains the constructor code to include in the contract.
	Constructor string
	// Functions contains additional functions to include in the contract.
	Functions string
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

// WithImport adds an import statement to the generated Solidity contract. Can
// be called multiple times to add multiple imports. The imports are sorted
// alphabetically for deterministic output.
//
// Example:
//
//	solidity.WithImport(strings.NewReader(`import { Mimc } from "../../../libraries/Mimc.sol";`))
func WithImport(r io.Reader) ExportOption {
	return func(cfg *ExportConfig) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("read import: %w", err)
		}
		if cfg.Imports == nil {
			cfg.Imports = make(map[string]struct{})
		}
		cfg.Imports[string(b)] = struct{}{}
		return nil
	}
}

// WithInterface adds an interface name that the contract implements. Can be
// called multiple times to add multiple interfaces.
//
// Example:
//
//	solidity.WithInterface(strings.NewReader("IPlonkVerifier"))
func WithInterface(r io.Reader) ExportOption {
	return func(cfg *ExportConfig) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("read interface: %w", err)
		}
		cfg.Interfaces = append(cfg.Interfaces, string(b))
		return nil
	}
}

// WithConstants adds additional constant declarations to the generated Solidity
// contract. The constants are inserted after the existing constants in the
// template.
//
// Example:
//
//	solidity.WithConstants(strings.NewReader("bytes32 private immutable CHAIN_CONFIGURATION;"))
func WithConstants(r io.Reader) ExportOption {
	return func(cfg *ExportConfig) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("read constants: %w", err)
		}
		cfg.Constants = string(b)
		return nil
	}
}

// WithConstructor adds a constructor to the generated Solidity contract.
//
// Example:
//
//	solidity.WithConstructor(strings.NewReader("constructor() { }"))
func WithConstructor(r io.Reader) ExportOption {
	return func(cfg *ExportConfig) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("read constructor: %w", err)
		}
		cfg.Constructor = string(b)
		return nil
	}
}

// WithFunctions adds additional functions to the generated Solidity contract.
// The functions are inserted before the closing brace of the contract.
//
// Example:
//
//	solidity.WithFunctions(strings.NewReader("function foo() public { }"))
func WithFunctions(r io.Reader) ExportOption {
	return func(cfg *ExportConfig) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("read functions: %w", err)
		}
		cfg.Functions = string(b)
		return nil
	}
}

// SortedImports returns the imports sorted alphabetically for deterministic output.
func (cfg *ExportConfig) SortedImports() []string {
	if len(cfg.Imports) == 0 {
		return nil
	}
	imports := make([]string, 0, len(cfg.Imports))
	for imp := range cfg.Imports {
		imports = append(imports, imp)
	}
	sort.Strings(imports)
	return imports
}

// InterfaceDeclaration returns the interface declaration string for the contract.
// Returns empty string if no interfaces are defined.
func (cfg *ExportConfig) InterfaceDeclaration() string {
	if len(cfg.Interfaces) == 0 {
		return ""
	}
	result := " is "
	for i, iface := range cfg.Interfaces {
		if i > 0 {
			result += ", "
		}
		result += iface
	}
	return result
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
