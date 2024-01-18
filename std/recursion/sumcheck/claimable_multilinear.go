package sumcheck

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

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
	fn.f.AssertIsEqual(val, expectedValue)
	return nil
}

type NativeMultilinearClaim struct {
	*bigIntEngine

	ml []*big.Int
}

func NewNativeMultilinearClaim(target *big.Int, ml []*big.Int) (claim *NativeMultilinearClaim, hypersum *big.Int, err error) {
	if bits.OnesCount(uint(len(ml))) != 1 {
		return nil, nil, fmt.Errorf("expecting power of two coeffs")
	}
	be := &bigIntEngine{mod: new(big.Int).Set(target)}
	hypersum = new(big.Int)
	for i := range ml {
		hypersum = be.Add(hypersum, hypersum, ml[i])
	}
	cml := make([]*big.Int, len(ml))
	for i := range ml {
		cml[i] = new(big.Int).Set(ml[i])
	}
	return &NativeMultilinearClaim{bigIntEngine: be, ml: cml}, hypersum, nil
}

func (fn *NativeMultilinearClaim) NbClaims() int {
	return 1
}

func (fn *NativeMultilinearClaim) NbVars() int {
	return bits.Len(uint(len(fn.ml))) - 1
}

func (fn *NativeMultilinearClaim) Combine(coeff *big.Int) NativePolynomial {
	return []*big.Int{fn.hypesumX1One()}
}

func (fn *NativeMultilinearClaim) ToUnivariate(r *big.Int) NativePolynomial {
	fn.ml = fn.fold(r)
	return []*big.Int{fn.hypesumX1One()}
}

func (fn *NativeMultilinearClaim) ProverFinalEval(r []*big.Int) NativeEvaluationProof {
	return nil
}

func (fn *NativeMultilinearClaim) fold(r *big.Int) []*big.Int {
	mid := len(fn.ml) / 2
	bottom, top := fn.ml[:mid], fn.ml[mid:]
	t := new(big.Int)
	for i := 0; i < mid; i++ {
		fn.Sub(t, top[i], bottom[i])
		fn.Mul(t, t, r)
		fn.Add(bottom[i], bottom[i], t)
	}
	return fn.ml[:mid]
}

func (fn *NativeMultilinearClaim) hypesumX1One() *big.Int {
	sum := fn.ml[len(fn.ml)/2]
	for i := len(fn.ml)/2 + 1; i < len(fn.ml); i++ {
		fn.Add(sum, sum, fn.ml[i])
	}
	return sum
}
