package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

// ECPairBLS implements [BLS12_PAIRING_CHECK] precompile contract at address 0x0f.
//
// To have a fixed-circuit regardless of the number of inputs, we need 2 fixed circuits:
//   - MillerLoopAndMul:
//     A Miller loop of fixed size 1 followed by a multiplication in 𝔽p¹².
//   - MillerLoopAndFinalExpCheck:
//     A Miller loop of fixed size 1 followed by a multiplication in 𝔽p¹², and
//     a check that the result lies in the same equivalence class as the
//     reduced pairing purported to be 1. This check replaces the final
//     exponentiation step in-circuit and follows Section 4 of [On Proving
//     Pairings] paper by A. Novakovic and L. Eagen.
//
// N.B.: This is a sub-optimal routine but defines a fixed circuit regardless
// of the number of inputs.  We can extend this routine to handle a 2-by-2
// logic but we prefer a minimal number of circuits (2).
//
// See the methods [ECPairMillerLoopAndMul] and [ECPairMillerLoopAndFinalExpCheck] for the fixed circuits.
// See the method [ECPairIsOnG2] for the check that Qᵢ are on G2.
//
// [BLS12_PAIRING_CHECK]: https://eips.ethereum.org/EIPS/eip-2537
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func ECPairBLS(api frontend.API, P []*sw_bls12381.G1Affine, Q []*sw_bls12381.G2Affine) {
	if len(P) != len(Q) {
		panic("P and Q length mismatch")
	}
	if len(P) < 2 {
		panic("invalid multipairing size bound")
	}
	n := len(P)
	pair, err := sw_bls12381.NewPairing(api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		// 1- Check that Pᵢ are on G1
		pair.AssertIsOnG1(P[i])
		// 2- Check that Qᵢ are on G2 (done in `computeLines` in `MillerLoopAndMul` and `MillerLoopAndFinalExpCheck)
	}

	// 3- Check that ∏ᵢ e(Pᵢ, Qᵢ) == 1
	ml := pair.Ext12.One()
	for i := 0; i < n-1; i++ {
		// fixed circuit 1
		ml, err = pair.MillerLoopAndMul(P[i], Q[i], ml)
		if err != nil {
			panic(err)
		}
	}

	// fixed circuit 2
	pair.AssertMillerLoopAndFinalExpIsOne(P[n-1], Q[n-1], ml)
}

// ECPairBLSIsOnG1 implements the fixed circuit for checking G1 membership and non-membership.
func ECPairBLSIsOnG1(api frontend.API, Q *sw_bls12381.G1Affine, expectedIsOnG1 frontend.Variable) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	isOnG1 := pairing.IsOnG1(Q)
	api.AssertIsEqual(expectedIsOnG1, isOnG1)
	return nil
}

// ECPairBLSIsOnG2 implements the fixed circuit for checking G2 membership and non-membership.
func ECPairBLSIsOnG2(api frontend.API, Q *sw_bls12381.G2Affine, expectedIsOnG2 frontend.Variable) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	isOnG2 := pairing.IsOnG2(Q)
	api.AssertIsEqual(expectedIsOnG2, isOnG2)
	return nil
}

// ECPairMillerLoopAndMul implements the fixed circuit for a Miller loop of
// fixed size 1 followed by a multiplication with an accumulator in 𝔽p¹². It
// asserts that the result corresponds to the expected result.
func ECPairBLSMillerLoopAndMul(api frontend.API, accumulator *sw_bls12381.GTEl, P *sw_bls12381.G1Affine, Q *sw_bls12381.G2Affine, expected *sw_bls12381.GTEl) error {
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	ml, err := pairing.MillerLoopAndMul(P, Q, accumulator)
	if err != nil {
		return fmt.Errorf("miller loop and mul: %w", err)
	}
	pairing.AssertIsEqual(expected, ml)
	return nil
}

// ECPairMillerLoopAndFinalExpCheck implements the fixed circuit for a Miller
// loop of fixed size 1 followed by a multiplication with an accumulator in
// 𝔽p¹², and a check that the result corresponds to the expected result.
func ECPairBLSMillerLoopAndFinalExpCheck(api frontend.API, accumulator *sw_bls12381.GTEl, P *sw_bls12381.G1Affine, Q *sw_bls12381.G2Affine, expectedIsSuccess frontend.Variable) error {
	api.AssertIsBoolean(expectedIsSuccess)
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	isSuccess := pairing.IsMillerLoopAndFinalExpOne(P, Q, accumulator)
	api.AssertIsEqual(expectedIsSuccess, isSuccess)
	return nil
}
