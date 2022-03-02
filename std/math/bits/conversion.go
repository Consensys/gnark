package bits

import (
	"errors"

	"github.com/consensys/gnark/frontend"
)

type Base uint8

const (
	Binary  Base = 2
	Ternary Base = 3
	Quinary Base = 5
)

// ToBase converts b in given base
func ToBase(api frontend.API, base Base, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	switch base {
	case Binary:
		return toBinary(api, v, opts...)
	default:
		panic("not implemented")
	}
}

// FromBase compute from a set of digits its canonical representation
// For example for base 2, it returns Σbi = Σ (2**i * b[i])
func FromBase(api frontend.API, base Base, digits ...frontend.Variable) frontend.Variable {
	if len(digits) == 0 {
		panic("FromBase needs at least 1 digit")
	}
	switch base {
	case Binary:
		return fromBinary(api, digits)
	default:
		panic("not implemented")
	}
}

type BaseConversionConfig struct {
	NbDigits      int
	Unconstrained bool
}

type BaseConversionOption func(opt *BaseConversionConfig) error

// WithNbDigits set the resulting number of digits to be used in the base conversion
// nbDigits must be > 0
func WithNbDigits(nbDigits int) BaseConversionOption {
	return func(opt *BaseConversionConfig) error {
		if nbDigits <= 0 {
			return errors.New("nbDigits <= 0")
		}
		opt.NbDigits = nbDigits
		return nil
	}
}

// WithUnconstrainedOutputs sets the bit conversion API to NOT constrain the output
// This is UNSAFE but is useful when the outputs are already constrained by other circuit
// constraints
func WithUnconstrainedOutputs() BaseConversionOption {
	return func(opt *BaseConversionConfig) error {
		opt.Unconstrained = true
		return nil
	}
}
