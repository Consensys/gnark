package hint

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
)

var initBuiltinOnce sync.Once

func init() {
	initBuiltinOnce.Do(func() {
		IsZero = NewStaticHint(builtinIsZero, 1, 1)
		Register(IsZero)
		IthBit = NewStaticHint(builtinIthBit, 2, 1)
		Register(IthBit)
	})
}

// The package provides the following built-in hint functions. All built-in hint
// functions are registered in the registry.
var (
	// IsZero computes the value 1 - a^(modulus-1) for the single input a. This
	// corresponds to checking if a == 0 (for which the function returns 1) or a
	// != 0 (for which the function returns 0).
	IsZero Function

	// IthBit returns the i-tb bit the input. The function expects exactly two
	// integer inputs i and n, takes the little-endian bit representation of n and
	// returns its i-th bit.
	IthBit Function
)

func builtinIsZero(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// get fr modulus
	q := curveID.Info().Fr.Modulus()

	// save input
	result.Set(inputs[0])

	// reuse input to compute q - 1
	qMinusOne := inputs[0].SetUint64(1)
	qMinusOne.Sub(q, qMinusOne)

	// result =  1 - input**(q-1)
	result.Exp(result, qMinusOne, q)
	inputs[0].SetUint64(1)
	result.Sub(inputs[0], result).Mod(result, q)

	return nil
}

func builtinIthBit(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	result := results[0]
	if !inputs[1].IsUint64() {
		result.SetUint64(0)
		return nil
	}

	result.SetUint64(uint64(inputs[0].Bit(int(inputs[1].Uint64()))))
	return nil
}
