package gkr

import (
	"fmt"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// solveHint the hint returns the outputs, indexed by output (ordered by SORTED circuit) first and instance second
func solveHint(data *circuitData) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {
		switch mod {
		case bn254.Modulus():
			return bn254SolveHint(data, ins, outs)
		}
		return fmt.Errorf("unknow modulus")
	}
}

func proveHint(data *circuitData) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {
		if data.typed == nil {
			return fmt.Errorf("attempting to run the prove hint before the solve hint is done. find a way to create a dependence between them (perhaps an output of the solver to be input to the prover as a hack)")
		}
		switch mod {
		case bn254.Modulus():
			return bn254ProveHint(data, ins, outs)
		}
		return fmt.Errorf("unknow modulus")
	}
}
