package gkr

import (
	"fmt"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	gnarkHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/big"
)

// solveHint the hint returns the outputs, indexed by output (ordered by SORTED circuit) first and instance second
func solveHint(data *circuitData) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {
		var err error
		if mod.Cmp(bn254.Modulus()) == 0 { // TODO: Switch case?
			data.typed, err = bn254SolveHint(data.noPtr, ins, outs)
		} else {
			err = fmt.Errorf("unknow modulus")
		}
		return err
	}
}

func proveHint(data interface{}, hash gnarkHash.Hash) func(*big.Int, []*big.Int, []*big.Int) error {
	hsh := hash.ToStandard()
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {
		if data == nil {
			return fmt.Errorf("attempting to run the prove hint before the solve hint is done. find a way to create a dependence between them (perhaps an output of the solver to be input to the prover as a hack)")
		}

		insAsBytes := algo_utils.Map(ins, func(i *big.Int) []byte {
			return i.Bytes()
		})

		var err error
		if mod.Cmp(bn254.Modulus()) == 0 { // TODO: Switch case?
			return bn254ProveHint(data.(bn254CircuitData), fiatshamir.WithHash(hsh, insAsBytes...), outs)
		} else {
			err = fmt.Errorf("unknow modulus")
		}
		return err
	}
}
