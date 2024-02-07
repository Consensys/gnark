package sumcheck

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

// LazyClaims allows to verify the sumcheck proof by allowing different final evaluations.
type LazyClaims[FR emulated.FieldParams] interface {
	// NbClaims is the number of parallel sumcheck proofs. If larger than one then sumcheck verifier computes a challenge for combining the claims.
	NbClaims() int
	// NbVars is the number of variables for the evaluatable function. Defines the number of rounds in the sumcheck protocol.
	NbVars() int
	// CombinedSum returns the folded claim for parallel verification.
	CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR]
	// Degree returns the maximum degree of the variable i-th variable.
	Degree(i int) int
	// AssertEvaluation (lazily) asserts the correctness of the evaluation value expectedValue of the claim at r.
	AssertEvaluation(r []*emulated.Element[FR], combinationCoeff, expectedValue *emulated.Element[FR], proof EvaluationProof) error
}

// claims is the interface for the claimable function for proving.
type claims interface {
	// NbClaims is the number of parallel sumcheck proofs. If larger than one then sumcheck verifier computes a challenge for combining the claims.
	NbClaims() int
	// NbVars is the number of variables for the evaluatable function. Defines the number of rounds in the sumcheck protocol.
	NbVars() int
	// Combine combines separate claims into a single sumcheckable claim using
	// the coefficient coeff.
	Combine(coeff *big.Int) nativePolynomial
	// Next fixes the next free variable to r, keeps the next variable free and
	// sums over a hypercube for the last variables. Instead of returning the
	// polynomial in coefficient form, it returns the evaluations at degree
	// different points.
	Next(r *big.Int) nativePolynomial
	// ProverFinalEval returns the (lazy) evaluation proof.
	ProverFinalEval(r []*big.Int) nativeEvaluationProof
}
