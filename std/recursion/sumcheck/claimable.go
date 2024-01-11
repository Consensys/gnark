package sumcheck

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
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

type Function[FR emulated.FieldParams] struct {
	ml    polynomial.Multilinear[FR]
	claim *emulated.Element[FR]

	f *emulated.Field[FR]
	p *polynomial.Polynomial[FR]
}

func NewMultiLinearClaim[FR emulated.FieldParams](api frontend.API, ml polynomial.Multilinear[FR], claim *emulated.Element[FR]) (*Function[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	return &Function[FR]{
		ml:    ml,
		claim: claim,
		f:     f,
		p:     p,
	}, nil
}

func (fn *Function[FR]) NbClaims() int {
	return 1
}

func (fn *Function[FR]) NbVars() int {
	return bits.Len(uint(len(fn.ml))) - 1
}

func (fn *Function[FR]) CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR] {
	return fn.claim
}

func (fn *Function[FR]) Degree(i int) int {
	// this is multlinear function - up to degree 1 in every variable
	return 1
}

func (fn *Function[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff *emulated.Element[FR], expectedValue *emulated.Element[FR], proof EvaluationProof) error {
	val, err := fn.p.EvalMultilinear(fn.ml, r)
	if err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	fn.f.AssertIsEqual(val, fn.claim)
	return nil
}
