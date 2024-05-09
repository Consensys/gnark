package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECMul implements [ALT_BN128_MUL] precompile contract at address 0x07.
//
// [ALT_BN128_MUL]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/alt_bn128/index.html#alt-bn128-mul
func ECMul(api frontend.API, P *sw_emulated.AffinePoint[emulated.BN254Fp], u *emulated.Element[emulated.BN254Fr]) *sw_emulated.AffinePoint[emulated.BN254Fp] {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		panic(err)
	}
	// Check that P is on the curve (done in the zkEVM ⚠️ )
	res := curve.ScalarMul(P, u, algopts.WithCompleteArithmetic())
	return res
}
