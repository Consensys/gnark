package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

// ECMapToG2BLS implements [BLS12_MAP_FP2_TO_G2] precompile contract at address 0x11.
//
// [ECMapToG2BLS]: https://eips.ethereum.org/EIPS/eip-2537
func ECMapToG2BLS(api frontend.API, u *fields_bls12381.E2, expected *sw_bls12381.G2Affine) error {
	g, err := sw_bls12381.NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2: %w", err)
	}
	res, err := g.MapToG2(u)
	if err != nil {
		return fmt.Errorf("map to G2: %w", err)
	}
	g.AssertIsEqual(res, expected)
	return nil
}
