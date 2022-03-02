package bits

import (
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

// ToBinary is an alias of ToBase(... Binary ...)
func ToBinary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	return ToBase(api, Binary, v, opts...)
}

// FromBinary is an alias of FromBase(... Binary ...)
func FromBinary(api frontend.API, digits ...frontend.Variable) frontend.Variable {
	return FromBase(api, Binary, digits...)
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
