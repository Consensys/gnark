package sumcheck

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

type Gate[AE ArithEngine[E], E Element] interface {
	Evaluate(api AE, dst E, vars ...E) E
	Degree() int // TODO: return degree of variable for optimized verification
}

type gateClaimMulti[FR emulated.FieldParams] struct {
	f  *emulated.Field[FR]
	p  *polynomial.Polynomial[FR]
	ee *emuEngine[FR]

	gate Gate[*emuEngine[FR], *emulated.Element[FR]]

	evaluationPoints   [][]*emulated.Element[FR]
	claimedEvaluations []*emulated.Element[FR]
}

func (g *gateClaimMulti[FR]) NbClaims() int {
	panic("not implemented") // TODO: Implement
}

func (g *gateClaimMulti[FR]) NbVars() int {
	panic("not implemented") // TODO: Implement
}

func (g *gateClaimMulti[FR]) CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR] {
	panic("not implemented") // TODO: Implement
}

func (g *gateClaimMulti[FR]) Degree(i int) int {
	panic("not implemented") // TODO: Implement
}

func (g *gateClaimMulti[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff *emulated.Element[FR], expectedValue *emulated.Element[FR], proof EvaluationProof) error {
	panic("not implemented") // TODO: Implement
}

type nativeGateClaim struct {
	ee *bigIntEngine

	gate Gate[*bigIntEngine, *big.Int]

	evaluationPoints   [][]*big.Int
	claimedEvaluations []*big.Int

	inputMultilin NativeMultilinear
}

func (g *nativeGateClaim) NbClaims() int {
	panic("not implemented") // TODO: Implement
}

func (g *nativeGateClaim) NbVars() int {
	panic("not implemented") // TODO: Implement
}

func (g *nativeGateClaim) Combine(coeff *big.Int) NativePolynomial {
	panic("not implemented") // TODO: Implement
}

func (g *nativeGateClaim) Next(r *big.Int) NativePolynomial {
	panic("not implemented") // TODO: Implement
}

func (g *nativeGateClaim) ProverFinalEval(r []*big.Int) NativeEvaluationProof {
	panic("not implemented") // TODO: Implement
}
