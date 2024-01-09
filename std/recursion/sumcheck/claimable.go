package sumcheck

import (
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

// TODO: make more specific
type EvaluationProof interface{}

// TODO: also make a method to create a claim-manager for a single function. Then can use sumcheck only without GKR.
type LazyClaims[FR emulated.FieldParams] interface {
	NbClaims() int
	NbVars() int
	CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR]
	Degree(i int) int
	// AssertEvaluation lazily asserts the correctness of the evaluation value expectedValue of the claim at r.
	AssertEvaluation(r []*emulated.Element[FR], combinationCoeff, expectedValue *emulated.Element[FR], proof EvaluationProof) error
}

type Proof[FR emulated.FieldParams] struct {
	PartialSumPolys []polynomial.Univariate[FR]
	// TODO: do we need to have the FinalEvalProof here? it would be good if we can move it to the claim manager.
	FinalEvalProof EvaluationProof
}
