package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECG2ScalarMulSumBLS computes the scalar multiplication of a point P by a
// scalar s in G2, adds it to a previous point prev, and checks that the result
// is equal to expected. It is used to implement the [BLS12_G2MSM] precompile
// contract at address 0x0e.
//
// [BLS12_G1MSM]: https://eips.ethereum.org/EIPS/eip-2537
func ECG2ScalarMulSumBLS(api frontend.API, prev, Q *sw_bls12381.G2Affine, s *emulated.Element[sw_bls12381.ScalarField], expected *sw_bls12381.G2Affine) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2: %w", err)
	}
	// Check the point is in G2
	g2.AssertIsOnG2(Q)
	// Compute the scalar multiplication
	res := g2.ScalarMul(Q, s, algopts.WithCompleteArithmetic())
	// Compute the aggregate
	sum := g2.AddUnified(prev, res)
	// Assert that the sum is as expected
	g2.AssertIsEqual(sum, expected)
	return nil
}
