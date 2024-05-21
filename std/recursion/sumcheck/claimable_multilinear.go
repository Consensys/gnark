package sumcheck

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

type multilinearClaim[FR emulated.FieldParams] struct {
	ml    polynomial.Multilinear[FR]
	claim *emulated.Element[FR]

	f *emulated.Field[FR]
	p *polynomial.Polynomial[FR]
}

func newMultilinearClaim[FR emulated.FieldParams](api frontend.API, ml polynomial.Multilinear[FR], claim *emulated.Element[FR]) (LazyClaims[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	return &multilinearClaim[FR]{
		ml:    ml,
		claim: claim,
		f:     f,
		p:     p,
	}, nil
}

func (fn *multilinearClaim[FR]) NbClaims() int {
	return 1
}

func (fn *multilinearClaim[FR]) NbVars() int {
	return bits.Len(uint(len(fn.ml))) - 1
}

func (fn *multilinearClaim[FR]) CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR] {
	return fn.claim
}

func (fn *multilinearClaim[FR]) Degree(i int) int {
	// this is multlinear function - up to degree 1 in every variable
	return 1
}

func (fn *multilinearClaim[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff *emulated.Element[FR], expectedValue *emulated.Element[FR], proof EvaluationProof) error {
	val, err := fn.p.EvalMultilinear(r, fn.ml)
	if err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	fn.f.AssertIsEqual(val, expectedValue)
	return nil
}

type nativeMultilinearClaim struct {
	be *bigIntEngine

	ml []*big.Int
}

func newNativeMultilinearClaim(target *big.Int, ml []*big.Int) (claim claims, hypersum *big.Int, err error) {
	if bits.OnesCount(uint(len(ml))) != 1 {
		return nil, nil, fmt.Errorf("expecting power of two coeffs")
	}
	be := newBigIntEngine(target)
	hypersum = new(big.Int)
	for i := range ml {
		hypersum = be.Add(hypersum, ml[i])
	}
	cml := make([]*big.Int, len(ml))
	for i := range ml {
		cml[i] = new(big.Int).Set(ml[i])
	}
	return &nativeMultilinearClaim{be: be, ml: cml}, hypersum, nil
}

func (fn *nativeMultilinearClaim) NbClaims() int {
	return 1
}

func (fn *nativeMultilinearClaim) NbVars() int {
	return bits.Len(uint(len(fn.ml))) - 1
}

func (fn *nativeMultilinearClaim) Combine(coeff *big.Int) nativePolynomial {
	return []*big.Int{hypersumX1One(fn.be, fn.ml)}
}

func (fn *nativeMultilinearClaim) Next(r *big.Int) nativePolynomial {
	fn.ml = fold(fn.be, fn.ml, r)
	return []*big.Int{hypersumX1One(fn.be, fn.ml)}
}

func (fn *nativeMultilinearClaim) ProverFinalEval(r []*big.Int) nativeEvaluationProof {
	// verifier computes the value of the multilinear function itself
	return nil
}
