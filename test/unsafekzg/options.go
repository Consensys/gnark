package unsafekzg

import (
	"os"
	"path/filepath"

	"github.com/consensys/gnark/logger"
)

type Option func(*config) error

// WithCacheDir enables the filesystem cache and sets the cache directory
// to ~/.gnark/kzg by default.
func WithFSCache() Option {
	return func(opt *config) error {
		opt.fsCache = true
		return nil
	}
}

// WithFflonk enables the construction of an SRS specific for fflonk,
// which is at least 15 times the SRS size required for plonk (and more
// if Commit is used)
func WithFflonk() Option {
	return func(opt *config) error {
		opt.fflonk = true
		return nil
	}
}

// WithNbCommitments specifies the number of calls to Commit
// in the circuit. It is necessary to know this data when fflonk
// is used, because the size of the SRS is (15+nb_calls_to_commit)*size(ccs)
func WithNbCommitments(nbCommitments int) Option {
	return func(opt *config) error {
		opt.nbCommitments = nbCommitments
		return nil
	}
}

type config struct {
	fsCache       bool
	cacheDir      string
	fflonk        bool
	nbCommitments int
}

// default options
func options(opts ...Option) (config, error) {
	var opt config

	// apply user provided options.
	for _, option := range opts {
		err := option(&opt)
		if err != nil {
			return opt, err
		}
	}

	// default value for cacheDir is ~/.gnark/kzg
	if opt.fsCache {
		if opt.cacheDir == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}
			opt.cacheDir = filepath.Join(homeDir, ".gnark", "kzg")
		}
		initCache(opt.cacheDir)
	}

	return opt, nil
}

func initCache(cacheDir string) {
	// get gnark logger
	log := logger.Logger()

	// populate cache from disk
	log.Warn().Str("cacheDir", cacheDir).Msg("using kzg srs cache")

	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		err := os.MkdirAll(cacheDir, 0700)
		if err != nil {
			panic(err)
		}
	}
}
