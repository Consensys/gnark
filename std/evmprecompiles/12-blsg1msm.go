package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECMSMG1BLS implements [BLS12_G1MSM] precompile contract at address 0x0c.
//
// [BLS12_G1MSM]: https://eips.ethereum.org/EIPS/eip-2537
func ECMSMG1BLS(api frontend.API, P []*sw_emulated.AffinePoint[emulated.BLS12381Fp], s []*emulated.Element[emulated.BLS12381Fr]) *sw_emulated.AffinePoint[emulated.BLS12381Fp] {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		panic(err)
	}

	// Check that all P's are on G1 (done in the zkEVM ⚠️ )
	res, err := curve.MultiScalarMul(P, s, algopts.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}

	return res
}
