package hint

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/gkr/hash"
	"math/big"
)

func init() {
	Register(InvZero)
	Register(MIMC2Elements)
	Register(MIMC2ElementsPure)
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

func MIMC2Elements(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	newState := new(fr.Element).SetBigInt(inputs[1])
	block := new(fr.Element).SetBigInt(inputs[0])
	oldState := new(fr.Element).SetBigInt(inputs[1])
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	results[0].SetBytes(bytes[:])
	return nil
}

func MIMC2ElementsPure(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	newState := new(fr.Element).SetBigInt(inputs[1])
	block := new(fr.Element).SetBigInt(inputs[0])
	oldState := new(fr.Element).SetBigInt(inputs[1])
	block.Sub(block, oldState)
	hash.MimcPermutationInPlace(newState, *block)
	bytes := newState.Bytes()
	results[0].SetBytes(bytes[:])
	return nil
}
