package hint

import (
	"math/big"
)

func init() {
	Register(InvZero)
}

// InvZero computes the value 1/a for the single input a. If a == 0, returns 0.
func InvZero(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// save input
	result.Set(inputs[0])

	// a == 0, return
	if result.IsUint64() && result.Uint64() == 0 {
		return nil
	}

	result.ModInverse(result, q)
	return nil
}
