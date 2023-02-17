package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

func init() {
	// register hints
	hint.Register(SelectionIndicators)
}

// Mux is an n to 1 multiplexer: out = inputs[sel]. In other words, it selects exactly one of its
// inputs based on sel. The index of inputs starts from zero.
//
// sel needs to be between 0 and n - 1 (inclusive), where n is the number of inputs, otherwise the proof will fail.
func Mux(api frontend.API, sel frontend.Variable, inputs ...frontend.Variable) (out frontend.Variable) {
	out = 0
	indicators, _ := api.Compiler().NewHint(SelectionIndicators, len(inputs), sel)
	indicatorsSum := frontend.Variable(0)
	for i := 0; i < len(inputs); i++ {
		// indicators[i] * (sel - i) == 0. Check that all indicators for inputs that are not selected, are zero.
		api.AssertIsEqual(api.Mul(indicators[i], api.Sub(sel, i)), 0)
		indicatorsSum = api.Add(indicatorsSum, indicators[i])
		// out += indicators[i] * inputs[i]
		out = api.Add(out, api.Mul(indicators[i], inputs[i]))
	}
	// We need to check that the indicator of the selected input is exactly 1. We used a sum constraint, cause usually
	// it is cheap.
	api.AssertIsEqual(indicatorsSum, 1)
	return out
}

func SelectionIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
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
