package gkr

import (
	"fmt"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

func proveHint(data interface{}) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {
		if data == nil {
			return fmt.Errorf("attempting to run the prove hint before the solve hint is done. find a way to create a dependence between them (perhaps an output of the solver to be input to the prover as a hack)")
		}
		switch mod {
		case bn254.Modulus():
			return bn254ProveHint(data.(bn254CircuitData), ins, outs)
		}
		return fmt.Errorf("unknow modulus")
	}
}
