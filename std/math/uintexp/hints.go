package uintexp

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in this package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		decodeHint,
	}
}

// decodeHint computes the discrete logarithm of an encoded value in the base
// ω of order 2^k. Inputs are [k, v] (the width is passed as a hint input as
// hints only receive the field modulus), output is [a] with v = ω^a.
//
// A failing hint makes the solver fail, but soundness does not rely on it:
// the caller constrains the returned exponent by re-encoding it and asserting
// equality with the input.
func decodeHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 1 {
		return errors.New("expecting one output")
	}
	if !inputs[0].IsUint64() {
		return errors.New("width must be uint64")
	}
	k := int(inputs[0].Uint64())
	a, err := decodeExp(q, k, inputs[1])
	if err != nil {
		return err
	}
	outputs[0].Set(a)
	return nil
}
