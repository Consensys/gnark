package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// ECPair implements [ALT_BN128_PAIRING_CHECK] precompile contract at address 0x08.
//
// [ALT_BN128_PAIRING_CHECK]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/alt_bn128/index.html#alt-bn128-pairing-check
//
// To have a fixed-circuit regardless of the number of inputs, we need 2 fixed circuits:
// - MillerLoopAndMul:
// 		A Miller loop of fixed size 1 followed by a multiplication in 𝔽p¹².
// - MillerLoopAndFinalExpCheck:
// 		A Miller loop of fixed size 1 followed by a multiplication in 𝔽p¹², and
// 		a check that the result lies in the same equivalence class as the
// 		reduced pairing purported to be 1. This check replaces the final
// 		exponentiation step in-circuit and follows Section 4 of [On Proving
// 		Pairings] paper by A.  Novakovic and L. Eagen.
//
// 		[On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
//
// N.B.: This is a sub-optimal routine but defines a fixed circuit regardless
// of the number of inputs.  We can extend this routine to handle a 2-by-2
// logic but we prefer a minimal number of circuits (2).

func ECPair(api frontend.API, P []*sw_bn254.G1Affine, Q []*sw_bn254.G2Affine) {
	if len(P) != len(Q) {
		panic("P and Q length mismatch")
	}
	if len(P) < 2 {
		panic("invalid multipairing size bound")
	}
	n := len(P)
	pair, err := sw_bn254.NewPairing(api)
	if err != nil {
		panic(err)
	}
	// 1- Check that Pᵢ are on G1 (done in the zkEVM ⚠️ )
	// 2- Check that Qᵢ are on G2
	for i := 0; i < len(Q); i++ {
		pair.AssertIsOnG2(Q[i])
	}

	// 3- Check that ∏ᵢ e(Pᵢ, Qᵢ) == 1
	ml := pair.One()
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
