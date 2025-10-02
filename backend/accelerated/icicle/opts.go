package icicle

import (
	"fmt"

	"github.com/consensys/gnark/backend"
)

// Config is the configuration for the ICICLE backend.
type Config struct {
	DeviceID    int
	Backend     Backend
	BackendLibs string
	ProverOpts  []backend.ProverOption
}

// NewConfig creates a new IcicleConfig with the given options. If no options
// are provided, it uses sensible defaults.
func NewConfig(opts ...Option) (*Config, error) {
	cfg := Config{
		DeviceID: 0,
		Backend:  CUDA,
	}
	for _, o := range opts {
		if o != nil {
			if err := o(&cfg); err != nil {
				return nil, err
			}
		}
	}
	return &cfg, nil
}

// Option is an option for the ICICLE backend. If no options are set, then
// sensible defaults are used (acceleration CUDA, device id 0).
type Option func(*Config) error

// Backend defines the type of backend to use for ICICLE acceleration.
type Backend int

const (
	CUDA Backend = iota
	CPU
	maxBackend
)

func (b Backend) String() string {
	switch b {
	case CUDA:
		return "CUDA"
	case CPU:
		return "CPU"
	default:
		return "unknown"
	}
}

// WithDeviceID sets the device IDs to be used by the ICICLE backend. When
// defining this option, then at least one device is required and other IDs are
// optional. If this option is not set then device ID 0 is used.
func WithDeviceID(id int) Option {
	return func(c *Config) error {
		if id < 0 {
			return fmt.Errorf("invalid device id %d", id)
		}
		c.DeviceID = id
		return nil
	}
}

// WithBackend sets the backend to be used by ICICLE frontend. If this option
// is not set then CUDA backend is used.
func WithBackend(backend Backend) Option {
	return func(c *Config) error {
		if backend < 0 || backend >= maxBackend {
			return fmt.Errorf("invalid backend %d", backend)
		}
		c.Backend = backend
		return nil
	}
}

// WithProverOptions sets prover options. See [backend.ProverOption] for details.
func WithProverOptions(opts ...backend.ProverOption) Option {
	return func(c *Config) error {
		if len(opts) == 0 {
			return fmt.Errorf("no prover options provided")
		}
		c.ProverOpts = opts
		return nil
	}
}

// WithBackendLibrary sets the location of the backend library. This overrides
// the environment variable `ICICLE_BACKEND_INSTALL_DIR`. If this option is not
// set, then the environment variable is used first and if the variable is not
// set, then the default search location is used.
func WithBackendLibrary(libs string) Option {
	return func(c *Config) error {
		if libs == "" {
			return fmt.Errorf("no backend libs provided")
		}
		c.BackendLibs = libs
		return nil
	}
}
