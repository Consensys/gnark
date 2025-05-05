package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECMSMG2BLS implements [BLS12_G2MSM] precompile contract at address 0x0e.
//
// [BLS12_G2MSM]: https://eips.ethereum.org/EIPS/eip-2537
func ECMSMG2BLS(api frontend.API, P []*sw_bls12381.G2Affine, s []*emulated.Element[emulated.BLS12381Fr]) *sw_bls12381.G2Affine {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		panic(err)
	}

	// Check that Pᵢ are on G2
	for _, p := range P {
		g2.AssertIsOnG2(p)
	}

	// Compute the MSM
	res, err := g2.MultiScalarMul(P, s, algopts.WithCompleteArithmetic())
	if err != nil {
		panic(err)
	}

	return res
}
