package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECMapToG1BLS implements[BLS12_MAP_FP_TO_G1] precompile contract at adress 0x10.
//
// [ECMapToG1BLS]: https://eips.ethereum.org/EIPS/eip-2537
func ECMapToG1BLS(api frontend.API, u *emulated.Element[emulated.BLS12381Fp]) *sw_emulated.AffinePoint[emulated.BLS12381Fp] {

	res, err := sw_bls12381.MapToG1(api, u)
	if err != nil {
		panic(err)
	}

	return res

}
