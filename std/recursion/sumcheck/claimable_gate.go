package sumcheck

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

type Gate[AE ArithEngine[E], E Element] interface {
	NbInputs() int
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
	engine *bigIntEngine

	gate Gate[*bigIntEngine, *big.Int]

	evaluationPoints   [][]*big.Int
	claimedEvaluations []*big.Int

	// inputPreprocessor is a slice of multilinear functions which map
	// multi-instance input id to the instance value. This allows running
	// sumcheck over the hypercube. Every element in the slice represents the
	// input.
	inputPreprocessor []NativeMultilinear

	eq NativeMultilinear
}

func (g *nativeGateClaim) NbClaims() int {
	return len(g.claimedEvaluations)
}

func (g *nativeGateClaim) NbVars() int {
	return g.gate.NbInputs()
}

func (g *nativeGateClaim) Combine(coeff *big.Int) NativePolynomial {
	nbVars := g.gate.NbInputs()
	eqLength := 1 << nbVars
	nbClaims := g.NbClaims()

	g.eq = make(NativeMultilinear, eqLength)
	g.eq[0] = g.engine.One()
	g.eq = eq(g.engine, g.eq, g.evaluationPoints[0])

	newEq := make(NativeMultilinear, eqLength)
	aI := new(big.Int).Set(coeff)

	for k := 1; k < nbClaims; k++ {
		newEq[0] = g.engine.One()
		g.eq = eqAcc(g.engine, g.eq, newEq, g.evaluationPoints[k])
		if k+1 < nbClaims {
			g.engine.Mul(aI, aI, coeff)
		}

	}
	return g.computeGJ()
}

func (g *nativeGateClaim) Next(r *big.Int) NativePolynomial {
	for i := range g.inputPreprocessor {
		g.inputPreprocessor[i] = fold(g.engine, g.inputPreprocessor[i], r)
	}
	g.eq = fold(g.engine, g.eq, r)
	return g.computeGJ()
}

func (g *nativeGateClaim) ProverFinalEval(r []*big.Int) NativeEvaluationProof {
	// verifier computes the value of the gate (times the eq) itself
	return nil
}

func (g *nativeGateClaim) computeGJ() NativePolynomial {
	// returns the polynomial GJ through its evaluations
	panic("todo")
}
