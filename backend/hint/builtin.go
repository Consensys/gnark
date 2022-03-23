package hint

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

func init() {
	Register(IsZero)
}

// IsZero computes the value 1 - a^(modulus-1) for the single input a. This
// corresponds to checking if a == 0 (for which the function returns 1) or a
// != 0 (for which the function returns 0).
func IsZero(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
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
