package unsafekzg

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/logger"
)

// Option allows changing the behaviour of the unsafe KZG SRS generation.
type Option func(*config) error

// WithCacheDir enables the filesystem cache and sets the cache directory
// to ~/.gnark/kzg by default.
func WithFSCache() Option {
	return func(opt *config) error {
		opt.fsCache = true
		return nil
	}
}

// WithCacheDir enables the filesystem cache and sets the cache directory
// to the provided path.
func WithCacheDir(dir string) Option {
	return func(opt *config) error {
		opt.fsCache = true
		opt.cacheDir = dir
		return nil
	}
}

// WithToxicValue sets the toxic value to the provided value.
//
// NB! This is a debug option and should not be used in production.
func WithToxicValue(toxicValue *big.Int) Option {
	return func(opt *config) error {
		if opt.toxicValue != nil {
			return errors.New("toxic value already set")
		}
		opt.toxicValue = toxicValue
		return nil
	}
}

// WithToxicSeed sets the toxic value to the sha256 hash of the provided seed.
//
// NB! This is a debug option and should not be used in production.
func WithToxicSeed(seed []byte) Option {
	return func(opt *config) error {
		if opt.toxicValue != nil {
			return errors.New("toxic value already set")
		}
		h := sha256.New()
		h.Write(seed)
		opt.toxicValue = new(big.Int)
		opt.toxicValue.SetBytes(h.Sum(nil))
		return nil
	}
}

type config struct {
	fsCache    bool
	cacheDir   string
	toxicValue *big.Int
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
