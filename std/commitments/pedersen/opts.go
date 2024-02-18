package pedersen

import "fmt"

type verifierCfg struct {
	subgroupCheck bool
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

// VerifierOption allows to modify the behaviour of Pedersen verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithSubgroupCheck returns a VerifierOption that forces subgroup check.
func WithSubgroupCheck() VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.subgroupCheck = true
		return nil
	}
}
