package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

// ECAddG2BLS implements [BLS12_G2ADD] precompile contract at address 0x0d.
//
// [BLS12_G2ADD]: https://eips.ethereum.org/EIPS/eip-2537
func ECAddG2BLS(api frontend.API, P, Q *sw_bls12381.G2Affine) *sw_bls12381.G2Affine {
	g2 := sw_bls12381.NewG2(api)
	// TODO @yelhousni: Check that P and Q are on the curve

	// We use AddUnified because P can be equal to Q, -Q and either or both can be (0,0)
	res := g2.AddUnified(P, Q)
	return res
}
