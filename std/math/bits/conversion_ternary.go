package bits

import (
	"math"
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

// ToTernary is an alias of ToBase(... Ternary ...)
func ToTernary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	return ToBase(api, Ternary, v, opts...)
}

// FromTernary is an alias of FromBase(... Ternary ...)
func FromTernary(api frontend.API, digits ...frontend.Variable) frontend.Variable {
	return FromBase(api, Ternary, digits...)
}

func fromTernary(api frontend.API, digits []frontend.Variable) frontend.Variable {
	// Σti = Σ (3**i * b[i])
	Σti := frontend.Variable(0)

	c := big.NewInt(1)
	base := big.NewInt(3)

	for i := 0; i < len(digits); i++ {
		// TODO ensures the digits are actual trits
		Σti = api.Add(Σti, api.Mul(c, digits[i])) // no constraint is recorded
		c.Mul(c, base)
	}

	return Σti
}

func toTernary(api frontend.API, v frontend.Variable, opts ...BaseConversionOption) []frontend.Variable {
	// parse options
	nbBits := api.Compiler().Curve().Info().Fr.Bits
	nbTrits := int(float64(nbBits)/math.Log2(3.0)) + 1
	cfg := BaseConversionConfig{
		NbDigits:      nbTrits,
		Unconstrained: false,
	}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			panic(err)
		}
	}

	// if a is a constant, work with the big int value.
	if c, ok := api.Compiler().ConstantValue(v); ok {
		trits := make([]frontend.Variable, cfg.NbDigits)
		// TODO using big.Int Text is likely not cheap
		base3 := c.Text(3)
		i := 0
		for j := len(base3) - 1; j >= 0 && i < len(trits); j-- {
			trits[i] = int(base3[j] - 48)
			i++
		}
		for ; i < len(trits); i++ {
			trits[i] = 0
		}
		return trits
	}

	c := big.NewInt(1)
	b := big.NewInt(3)

	trits, err := api.Compiler().NewHint(hint.NTrits, cfg.NbDigits, v)
	if err != nil {
		panic(err)
	}

	var Σti frontend.Variable
	Σti = 0
	for i := 0; i < cfg.NbDigits; i++ {
		Σti = api.Add(Σti, api.Mul(trits[i], c))
		c.Mul(c, b)
		if !cfg.Unconstrained {
			AssertIsTrit(api, trits[i])
		}
	}

	// record the constraint Σ (3**i * t[i]) == a
	api.AssertIsEqual(Σti, v)

	return trits
}

// AssertIsTrit constrain digit to be 0, 1 or 2
func AssertIsTrit(api frontend.API, v frontend.Variable) {
	if c, ok := api.Compiler().ConstantValue(v); ok {
		if c.IsUint64() && c.Uint64() <= 2 {
			return
		}
		panic("value " + c.String() + " is not 0, 1 or 2")
	}

	// v * (1 - v) * (2 - v) == 0
	// TODO this adds 3 constraint, not 2. Need api.Compiler().AddConstraint(...)
	y := api.Mul(api.Sub(1, v), api.Sub(2, v))
	api.AssertIsEqual(api.Mul(v, y), 0)
}
