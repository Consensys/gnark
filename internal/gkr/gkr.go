package gkr

import (
	"fmt"
	bn254Fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/internal/gkr/bn254"
	"math/big"
)

// hack to avoid import cycles. find out how to avoid

func SolveHint(data interface{}) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {
		switch mod {
		case bn254Fr.Modulus():
			return bn254.SolveHint(data, ins, outs)
		}
		return fmt.Errorf("unknow modulus")
	}
}
