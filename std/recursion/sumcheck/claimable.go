package sumcheck

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
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

type Claims interface {
	Combine(*big.Int) []*big.Int
	Next(*big.Int) []*big.Int
	NbVars() int
	NbClaims() int
	ProverFinalEval(r []*big.Int) NativeEvaluationProof
}

type MultilinearClaim[FR emulated.FieldParams] struct {
	ml    polynomial.Multilinear[FR]
	claim *emulated.Element[FR]

	f *emulated.Field[FR]
	p *polynomial.Polynomial[FR]
}

func NewMultilinearClaim[FR emulated.FieldParams](api frontend.API, ml polynomial.Multilinear[FR], claim *emulated.Element[FR]) (*MultilinearClaim[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	return &MultilinearClaim[FR]{
		ml:    ml,
		claim: claim,
		f:     f,
		p:     p,
	}, nil
}

func (fn *MultilinearClaim[FR]) NbClaims() int {
	return 1
}

func (fn *MultilinearClaim[FR]) NbVars() int {
	return bits.Len(uint(len(fn.ml))) - 1
}

func (fn *MultilinearClaim[FR]) CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR] {
	return fn.claim
}

func (fn *MultilinearClaim[FR]) Degree(i int) int {
	// this is multlinear function - up to degree 1 in every variable
	return 1
}

func (fn *MultilinearClaim[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff *emulated.Element[FR], expectedValue *emulated.Element[FR], proof EvaluationProof) error {
	val, err := fn.p.EvalMultilinear(fn.ml, r)
	if err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	fn.f.AssertIsEqual(val, fn.claim)
	return nil
}

func getChallengeNames(prefix string, nbClaims int, nbVars int) []string {
	var challengeNames []string
	if nbClaims > 1 {
		challengeNames = []string{prefix + "comb"}
	}
	for i := 0; i < nbVars; i++ {
		challengeNames = append(challengeNames, fmt.Sprintf("%spSP.%d", prefix, i))
	}
	return challengeNames
}
