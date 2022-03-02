package hint

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

var (
	// IsZero computes the value 1 - a^(modulus-1) for the single input a. This
	// corresponds to checking if a == 0 (for which the function returns 1) or a
	// != 0 (for which the function returns 0).
	IsZero = NewStaticHint(isZero)

	// IthBit returns the i-tb bit the input. The function expects exactly two
	// integer inputs i and n, takes the little-endian bit representation of n and
	// returns its i-th bit.
	IthBit = NewStaticHint(ithBit)

	// NBits returns the n first bits of the input. Expects one argument: n.
	NBits = NewStaticHint(nBits)

	// NTrits returns the n first bits of the input. Expects one argument: n.
	NTrits = NewStaticHint(nTrits)
)

func init() {
	Register(IsZero)
	Register(IthBit)
	Register(NBits)
	Register(NTrits)
}

func isZero(curveID ecc.ID, inputs []*big.Int, results []*big.Int) error {
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

func ithBit(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	result := results[0]
	if !inputs[1].IsUint64() {
		result.SetUint64(0)
		return nil
	}

	result.SetUint64(uint64(inputs[0].Bit(int(inputs[1].Uint64()))))
	return nil
}

func nBits(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	for i := 0; i < len(results); i++ {
		results[i].SetUint64(uint64(n.Bit(i)))
	}
	return nil
}

func nTrits(_ ecc.ID, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	// TODO using big.Int Text method is likely not cheap
	base3 := n.Text(3)
	i := 0
	for j := len(base3) - 1; j >= 0 && i < len(results); j-- {
		results[i].SetUint64(uint64(base3[j] - 48))
		i++
	}
	for ; i < len(results); i++ {
		results[i].SetUint64(0)
	}

	return nil
}
