package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECAdd implements [ALT_BN128_ADD] precompile contract at address 0x06.
//
// [ALT_BN128_ADD]: https://github.com/ethereum/execution-specs/blob/master/src/ethereum/cancun/vm/precompiled_contracts/alt_bn128.py
func ECAdd(api frontend.API, P, Q *sw_emulated.AffinePoint[emulated.BN254Fp]) *sw_emulated.AffinePoint[emulated.BN254Fp] {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		panic(err)
	}
	// Check that P and Q are on G1 (done in the zkEVM ⚠️ )
	// We use AddUnified because P can be equal to Q, -Q and either or both can be (0,0)
	res := curve.AddUnified(P, Q)
	return res
}
