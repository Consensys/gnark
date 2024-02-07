package sumcheck

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

type LazyClaims[FR emulated.FieldParams] interface {
	NbClaims() int
	NbVars() int
	// CombinedSum returns the folded claim. This is used when reducing the claim.
	CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR]
	// Degree returns the maximum degree of the variable i-th variable.
	Degree(i int) int
	// AssertEvaluation lazily asserts the correctness of the evaluation value expectedValue of the claim at r.
	AssertEvaluation(r []*emulated.Element[FR], combinationCoeff, expectedValue *emulated.Element[FR], proof EvaluationProof) error
}

// Claims is the interface for the claimable function for proving.
type claims interface {
	NbClaims() int
	NbVars() int
	// Combine combines separate claims into a single sumcheckable claim using
	// the coefficient coeff. It returns the combined claim.
	//
	// TODO: should we return a new [Claim] instead to make it stateless?
	Combine(coeff *big.Int) nativePolynomial

	// Next fixes the first len(r) variables to r, keeps the next
	// variable free and sums over a hypercube for the last variables. Instead
	// of returning the polynomial in coefficient form, it returns the
	// evaluations at degree different points.
	Next(r *big.Int) nativePolynomial
	ProverFinalEval(r []*big.Int) nativeEvaluationProof
}
