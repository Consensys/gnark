package bits

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

type Base uint8

const (
	Binary  Base = 2
	Ternary Base = 3
	Quinary Base = 5
)

// ToBinary is an alias of ToBase(... Binary ...)
func ToBinary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	return ToBase(api, Binary, v, opts...)
}

// FromBinary is an alias of FromBase(... Binary ...)
func FromBinary(api frontend.API, digits ...frontend.Variable) frontend.Variable {
	return FromBase(api, Binary, digits...)
}

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

func fromBinary(api frontend.API, digits []frontend.Variable) frontend.Variable {
	// Σbi = Σ (2**i * b[i])
	Σbi := frontend.Variable(0)

	c := big.NewInt(1)

	for i := 0; i < len(digits); i++ {
		// TODO do we want to keep this AssertIsBoolean here?
		api.AssertIsBoolean(digits[i])            // ensures the digits are actual bits
		Σbi = api.Add(Σbi, api.Mul(c, digits[i])) // no constraint is recorded
		c.Lsh(c, 1)
	}

	return Σbi
}

func toBinary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	// parse options
	cfg := BaseConversionConfig{
		NbDigits:      api.Compiler().Curve().Info().Fr.Bits,
		Unconstrained: false,
	}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			panic(err)
		}
	}

	// if a is a constant, work with the big int value.
	if c, ok := api.Compiler().ConstantValue(v); ok {
		bits := make([]frontend.Variable, cfg.NbDigits)
		for i := 0; i < len(bits); i++ {
			bits[i] = c.Bit(i)
		}
		return bits
	}

	var c big.Int
	c.SetUint64(1)

	bits, err := api.Compiler().NewHint(hint.NBits, cfg.NbDigits, v)
	if err != nil {
		panic(err)
	}

	var Σbi frontend.Variable
	Σbi = 0
	for i := 0; i < cfg.NbDigits; i++ {
		Σbi = api.Add(Σbi, api.Mul(bits[i], c))
		c.Lsh(&c, 1)
		if !cfg.Unconstrained {
			api.AssertIsBoolean(bits[i])
		}
	}

	// record the constraint Σ (2**i * b[i]) == a
	api.AssertIsEqual(Σbi, v)

	return bits
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
