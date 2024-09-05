package solidity

// ExportOption defines option for altering the behavior of the prover in
// Prove, ReadAndProve and IsSolved methods. See the descriptions of functions
// returning instances of this type for implemented options.
type ExportOption func(*ExportConfig) error

// ExportConfig is the configuration for the prover with the options applied.
type ExportConfig struct {
	PragmaVersion string
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
