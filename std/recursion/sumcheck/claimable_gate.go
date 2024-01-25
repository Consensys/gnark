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

	// inputPreprocessors is a slice of multilinear functions which map
	// multi-instance input id to the instance value. This allows running
	// sumcheck over the hypercube. Every element in the slice represents the
	// input.
	inputPreprocessors []NativeMultilinear

	eq NativeMultilinear
}

func NewNativeGate(target *big.Int, gate Gate[*bigIntEngine, *big.Int], inputs [][]*big.Int) (claim Claims, evaluations []*big.Int, err error) {
	be := newBigIntEngine(target)
	inputPreprocessors := make([]NativeMultilinear, gate.NbInputs())
	// TODO: pad input to power of two
	for i := range inputs {
		inputPreprocessors[i] = make(NativeMultilinear, len(inputs))
		for j := range inputs[i] {
			inputPreprocessors[i][j] = new(big.Int).Set(inputs[j][i])
		}
	}
	evaluations = make([]*big.Int, len(inputs))
	for i := range evaluations {
		evaluations[i] = new(big.Int)
		evaluations[i] = gate.Evaluate(be, evaluations[i], inputPreprocessors[i]...)
	}
	claimedEvaluations := make([]*big.Int, 1)
	challenge := big.NewInt(123) // TODO: compute correct challenge. Or isn't needed?
	claimedEvaluations[0] = eval(be, evaluations, []*big.Int{challenge})

	return &nativeGateClaim{
		engine:             be,
		gate:               gate,
		evaluationPoints:   [][]*big.Int{{challenge}},
		claimedEvaluations: claimedEvaluations,
		inputPreprocessors: inputPreprocessors,
		eq:                 nil,
	}, claimedEvaluations, nil
}

func (g *nativeGateClaim) NbClaims() int {
	return len(g.claimedEvaluations)
}

func (g *nativeGateClaim) NbVars() int {
	return len(g.evaluationPoints[0])
}

func (g *nativeGateClaim) Combine(coeff *big.Int) NativePolynomial {
	nbVars := g.NbVars()
	eqLength := 1 << nbVars
	nbClaims := g.NbClaims()

	g.eq = make(NativeMultilinear, eqLength)
	g.eq[0] = g.engine.One()
	for i := 1; i < eqLength; i++ {
		g.eq[i] = new(big.Int)
	}
	g.eq = eq(g.engine, g.eq, g.evaluationPoints[0])

	newEq := make(NativeMultilinear, eqLength)
	for i := 1; i < eqLength; i++ {
		newEq[i] = new(big.Int)
	}
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
	for i := range g.inputPreprocessors {
		g.inputPreprocessors[i] = fold(g.engine, g.inputPreprocessors[i], r)
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
	degGJ := 1 + g.gate.Degree()
	nbGateIn := len(g.inputPreprocessors)

	s := make([]NativeMultilinear, nbGateIn+1)
	s[0] = g.eq
	copy(s[1:], g.inputPreprocessors)

	nbInner := len(s)
	nbOuter := len(s[0]) / 2

	gJ := make(NativePolynomial, degGJ)
	for i := range gJ {
		gJ[i] = new(big.Int)
	}

	step := new(big.Int)
	res := make([]*big.Int, degGJ)
	for i := range res {
		res[i] = new(big.Int)
	}
	operands := make([]*big.Int, degGJ*nbInner)
	for i := range operands {
		operands[i] = new(big.Int)
	}

	for i := 0; i < nbOuter; i++ {
		block := nbOuter + i
		for j := 0; j < nbInner; j++ {
			// TODO: instead of set can assign?
			step.Set(s[j][block])
			operands[j].Set(s[j][block])
			g.engine.Sub(step, operands[j], step)
			for d := 1; d < degGJ; d++ {
				g.engine.Add(operands[d*nbInner+j], operands[(d-1)*nbInner+j], step)
			}
		}
		_s := 0
		_e := nbInner
		for d := 0; d < degGJ; d++ {
			summand := new(big.Int)
			g.gate.Evaluate(g.engine, summand, operands[_s+1:_e]...)
			g.engine.Mul(summand, summand, operands[_s])
			g.engine.Add(res[d], res[d], summand)
			_s, _e = _e, _e+nbInner
		}
	}
	for i := 0; i < degGJ; i++ {
		g.engine.Add(gJ[i], gJ[i], res[i])
	}
	return gJ
}
