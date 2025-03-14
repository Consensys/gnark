package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECAddBLS implements [BLS12_G1ADD] precompile contract at address 0x0b.
//
// [BLS12_G1ADD]: https://eips.ethereum.org/EIPS/eip-2537
func ECAddBLS(api frontend.API, P, Q *sw_emulated.AffinePoint[emulated.BLS12381Fp]) *sw_emulated.AffinePoint[emulated.BLS12381Fp] {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		panic(err)
	}
	// Check that P and Q are on G1 (done in the zkEVM ⚠️ )
	// We use AddUnified because P can be equal to Q, -Q and either or both can be (0,0)
	res := curve.AddUnified(P, Q)
	return res
}
