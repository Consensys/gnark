package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// ECPair implements [ALT_BN128_PAIRING_CHECK] precompile contract at address 0x08.
//
// [ALT_BN128_PAIRING_CHECK]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/alt_bn128/index.html#alt-bn128-pairing-check
//
// To have a fixed-circuit regardless of the number of inputs, we need 4 fixed circuits:
// - Fixed-size Miller loop (n=1)
// - Fixed-size Miller loop (n=2)
// - Multiplication in Fp12
// - Final exponentiation
//
// Examples:
// Batch 1: P1 ∈ G1 and Q1 ∈ G2
// Batch 2: P1, P2 ∈ G1 and Q1, Q2 ∈ G2
// Batch 3: P1, P2, P3 ∈ G1 and Q1, Q2, Q3 ∈ G2
// Batch 4: P1, P2, P3, P4 ∈ G1 and Q1, Q2, Q3, Q4 ∈ G2
// Batch 5: P1, P2, P3, P4, P5 ∈ G1 and Q1, Q2, Q3, Q4, Q5 ∈ G2
//
// * Batch 1 should never occur because e(P,Q)≠1 ∀P, Q ∈ G1, G2. So the precompile
//   would fail anyway.
// * Batch 2 occurs for e.g. BLS signature (single) verification, KZG verification...
//   e(P1,Q1)*e(P2,Q2) = | ml := MillerLoop2({P1,P1},{Q1,Q2})
// 					     | f := FinalExponentiation(ml)
// * Batch 3 occurs for e.g. QAP divisibility check in Pinocchio protocol verification.
//   e(P1,Q1)*e(P2,Q2)*e(P3,Q3) = | ml1 := MillerLoop2({P1,P2},{Q1,Q2})
// 							      | ml2 := MillerLoop1(P3,Q3)
// 					  		      | ml := Mul(ml1, ml2)
// 					  	          | f := FinalExponentiation(ml)
// * Batch 4 occurs for e.g. Groth16 verification.
//   e(P1,Q1)*e(P2,Q2)*e(P3,Q3)*e(P4,Q4) = | ml1 := MillerLoop2({P1,P2},{Q1,Q2})
//                                         | ml2 := MillerLoop2({P3,P4},{Q3,Q4})
// 					  		   	           | ml := Mul(ml1, ml2)
// 					  	       	           | f := FinalExponentiation(ml)
// * Batch 5 might occur for e.g. BLS signature (aggregated) verification.
//   e(P1,Q1)*e(P2,Q2)*e(P3,Q3)*e(P4,Q4)*e(P5,Q5) = | ml1 := MillerLoop2({P1,P2},{Q1,Q2})
//                                                  | ml2 := MillerLoop2({P3,P4},{Q3,Q4})
//                                                  | ml3 := MillerLoop1(P5,Q5)
// 					  		   	                    | ml := Mul(ml1, ml2)
// 					  		   	                    | ml = Mul(ml, ml3)
// 					  	       	                    | f := FinalExponentiation(ml)
//
//   N.B.: Batches 3, 4 and 5 are sub-optimal compared to Pair() but the result is
//   a fixed-circuit.

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
	i := 1
	ml, err := pair.MillerLoop([]*sw_bn254.G1Affine{P[i-1], P[i]}, []*sw_bn254.G2Affine{Q[0], Q[1]})
	if err != nil {
		panic(err)
	}
	acc := ml

	for i < n-2 {
		ml, err = pair.MillerLoop([]*sw_bn254.G1Affine{P[i+1], P[i+2]}, []*sw_bn254.G2Affine{Q[i+1], Q[i+2]})
		if err != nil {
			panic(err)
		}
		acc = pair.Mul(ml, acc)
		i += 2
	}

	if n%2 != 0 {
		ml, err = pair.MillerLoop([]*sw_bn254.G1Affine{P[n-1]}, []*sw_bn254.G2Affine{Q[n-1]})
		if err != nil {
			panic(err)
		}
		acc = pair.Mul(ml, acc)
	}

	res := pair.FinalExponentiation(acc)
	one := pair.One()
	pair.AssertIsEqual(res, one)
}
