package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

func init() {
	// register hints
	hint.Register(MuxIndicators)
	hint.Register(LookupIndicators)
}

// Lookup is a key value lookup table: the output will be values[i] such that keys[i] == sel. If keys does not
// contain sel, no proofs can be generated. If keys has more than one key that equals to sel, the output will
// be undefined, and the output could be a linear combination of the corresponding values with those keys.
//
// In case keys and values do not have the same length, this function will panic.
func Lookup(api frontend.API, sel frontend.Variable,
	keys []frontend.Variable, values []frontend.Variable) frontend.Variable {
	// we don't need this check, but we added it to produce more informative errors and disallow
	// len(keys) < len(values) which is supported by generateSelector.
	if len(keys) != len(values) {
		panic("The number of keys and values must be equal")
	}
	return generateSelector(api, false, sel, keys, values)
}

// Mux is an n to 1 multiplexer: out = inputs[sel]. In other words, it selects exactly one of its
// inputs based on sel. The index of inputs starts from zero.
//
// sel needs to be between 0 and n - 1 (inclusive), where n is the number of inputs, otherwise the proof will fail.
func Mux(api frontend.API, sel frontend.Variable, inputs ...frontend.Variable) frontend.Variable {
	return generateSelector(api, true, sel, nil, inputs)
}

// generateSelector generates a circuit for a multiplexer or a lookup table. If wantMux is true, a multiplexer is
// generated and keys are ignored. If wantMux is false, a lookup table is generated and we must have
// len(keys) <= len(values), otherwise it panics.
func generateSelector(api frontend.API, wantMux bool, sel frontend.Variable,
	keys []frontend.Variable, values []frontend.Variable) (out frontend.Variable) {

	var indicators []frontend.Variable
	if wantMux {
		indicators, _ = api.Compiler().NewHint(MuxIndicators, len(values), sel)
	} else {
		indicators, _ = api.Compiler().NewHint(LookupIndicators, len(keys), append(keys, sel)...)
	}

	out = 0
	indicatorsSum := frontend.Variable(0)
	for i := 0; i < len(indicators); i++ {
		// Check that all indicators for inputs that are not selected, are zero.
		if wantMux {
			// indicators[i] * (sel - i) == 0
			api.AssertIsEqual(api.Mul(indicators[i], api.Sub(sel, i)), 0)
		} else {
			// indicators[i] * (sel - keys[i]) == 0
			api.AssertIsEqual(api.Mul(indicators[i], api.Sub(sel, keys[i])), 0)
		}
		indicatorsSum = api.Add(indicatorsSum, indicators[i])
		// out += indicators[i] * values[i]
		out = api.MulAcc(out, indicators[i], values[i])
	}
	// We need to check that the indicator of the selected input is exactly 1. We used a sum constraint, because usually
	// it is cheap.
	api.AssertIsEqual(indicatorsSum, 1)
	return out
}

func MuxIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	sel := inputs[0]
	for i := 0; i < len(results); i++ {
		// i is an int which can be int32 or int64. We convert i to int64 then to bigInt, which is safe. We should
		// not convert sel to int64.
		if sel.Cmp(big.NewInt(int64(i))) == 0 {
			results[i].SetUint64(1)
		} else {
			results[i].SetUint64(0)
		}
	}
	return nil
}

func LookupIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	key := inputs[len(inputs)-1]
	// We must make sure that we are initializing all elements of results
	for i := 0; i < len(results); i++ {
		if key.Cmp(inputs[i]) == 0 {
			results[i].SetUint64(1)
		} else {
			results[i].SetUint64(0)
		}
	}
	return nil
}
