// Package sumcheck implements non-native sumcheck verifier.
//
// Sumcheck protocol is an interactive protocol between the prover and verifier
// to prove the evaluation
//
//	H = ∑_{x_j ∈ {0,1}, 1 ≤ j ≤ n} g((x_j)_{1 ≤ j ≤ n})
//
// for a multivariate function g: 𝔽ⁿ -> 𝔽.
//
// The sumcheck protocol runs in rounds, where first the prover sends the
// claimed value H, then the verifier sends in every round i random challenge
// r_i for which the prover responds with the univariate polynomial g_i(X)
//
//	g_i(X) = ∑_{x_j ∈ {0,1}, j ≥ i+1} g((r_j)_{j < i}, X, (x_j)_{j ≥ i+1}).
//
// The verifier checks that gᵢ(r_i) = gᵢ₊₁(0) + gᵢ₊₁(1) for every round. After
// the last round the verifier has to evaluate g((r_j){1 ≤ j ≤ n}) on its own.
//
// To allow for incorporating the sumcheck protocol inside a larger GKR
// protocol, parallel verification and different types of function g, the
// protocol instead defines [LazyClaims] interface which defines the aspects of
// the claimable function:
//   - the number of parallel proofs being verified (method [LazyClaims.NbClaims]) and the combined folded evaluation (method [LazyClaims.CominedSum]).
//   - the number of variables the function takes (method [LazyClaims.NbVars])
//   - the degree of the univariate polynomial for the i-th variable (method [LazyClaims.Degree])
//   - how to perform the final evaluation of the function (method [LazyClaims.AssertEvaluation]):
//   - the claim can directly evaluate the function itself (plain sumcheck),
//   - the evaluation is deferred as an input to another sumcheck protocol run (as in GKR),
//   - by opening a multivariate polynomial opening by letting prover to provide the opening proof.
//
// The package is still work in progress. We do not yet expose prover for
// creating the sumcheck proofs but aim to integrate the proof creation to be
// automatic given the specific claim type.
package sumcheck
