package sumcheck

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

type Gate[AE ArithEngine[E], E Element] interface {
	NbInputs() int
	Evaluate(api AE, vars ...E) E
	Degree() int // TODO: return degree of variable for optimized verification
}

type gateClaimMulti[FR emulated.FieldParams] struct {
	f      *emulated.Field[FR]
	p      *polynomial.Polynomial[FR]
	engine *emuEngine[FR]

	gate Gate[*emuEngine[FR], *emulated.Element[FR]]

	evaluationPoints   [][]*emulated.Element[FR]
	claimedEvaluations []*emulated.Element[FR]

	inputPreprocessors []polynomial.Multilinear[FR]
}

func NewGate[FR emulated.FieldParams](api frontend.API, gate Gate[*emuEngine[FR], *emulated.Element[FR]],
	inputs [][]*emulated.Element[FR], evaluationPoints [][]*emulated.Element[FR],
	claimedEvals []*emulated.Element[FR]) (*gateClaimMulti[FR], error) {
	nbInputs := gate.NbInputs()
	if len(inputs) != nbInputs {
		return nil, fmt.Errorf("expected %d inputs got %d", nbInputs, len(inputs))
	}
	if len(evaluationPoints) != len(claimedEvals) {
		return nil, fmt.Errorf("number of evaluation points %d do not match claimed evaluations %d", len(evaluationPoints), len(claimedEvals))
	}
	if len(inputs[0]) == 0 {
		return nil, fmt.Errorf("at least one input expected")
	}
	nbInstances := len(inputs[0])
	nbVars := bits.Len(uint(nbInstances)) - 1
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	engine, err := newEmulatedEngine[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new emulated engine: %w", err)
	}
	inputPreprocessors := make([]polynomial.Multilinear[FR], gate.NbInputs())
	for i := range inputs {
		if len(inputs[i]) != nbInstances {
			return nil, fmt.Errorf("nb of instances %d for input %d not %d", len(inputs[i]), i, nbInstances)
		}
		inputPreprocessors[i] = polynomial.FromSliceReferences(inputs[i])
	}
	for i := range evaluationPoints {
		if len(evaluationPoints[i]) != nbVars {
			return nil, fmt.Errorf("nb evaluation points %d mismatch for claim %d", len(evaluationPoints), i)
		}
	}
	return &gateClaimMulti[FR]{
		f:                  f,
		p:                  p,
		engine:             engine,
		gate:               gate,
		inputPreprocessors: inputPreprocessors,
		evaluationPoints:   evaluationPoints,
		claimedEvaluations: claimedEvals,
	}, nil
}

func (g *gateClaimMulti[FR]) NbClaims() int {
	return len(g.evaluationPoints)
}

func (g *gateClaimMulti[FR]) NbVars() int {
	return len(g.evaluationPoints[0])
}

func (g *gateClaimMulti[FR]) CombinedSum(coeff *emulated.Element[FR]) *emulated.Element[FR] {
	evalAsPoly := polynomial.FromSliceReferences[FR](g.claimedEvaluations)
	ret := g.p.EvalUnivariate(evalAsPoly, coeff)
	return ret
}

func (g *gateClaimMulti[FR]) Degree(i int) int {
	return 1 + g.gate.Degree()
}

func (g *gateClaimMulti[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff *emulated.Element[FR], expectedValue *emulated.Element[FR], proof EvaluationProof) error {
	var err error
	// TODO: handle case when have multiple claims
	if g.NbClaims() > 1 {
		panic("NbClaims > 1 not implemented")
	}
	eqEval := g.p.EvalEqual(g.evaluationPoints[0], r)
	inputEvals := make([]*emulated.Element[FR], len(g.inputPreprocessors))
	for i := range inputEvals {
		inputEvals[i], err = g.p.EvalMultilinear(g.inputPreprocessors[i], r)
		if err != nil {
			return fmt.Errorf("eval multilin: %w", err)
		}
	}
	gateEval := g.gate.Evaluate(g.engine, inputEvals...)
	res := g.f.Mul(eqEval, gateEval)
	g.f.AssertIsEqual(res, expectedValue)
	return nil
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

func NewNativeGate(target *big.Int, gate Gate[*bigIntEngine, *big.Int], inputs [][]*big.Int, evaluationPoints [][]*big.Int) (claim Claims, evaluations []*big.Int, err error) {
	be := newBigIntEngine(target)
	nbInputs := gate.NbInputs()
	if len(inputs) != nbInputs {
		return nil, nil, fmt.Errorf("expected %d inputs got %d", nbInputs, len(inputs))
	}
	nbInstances := len(inputs[0])
	nbVars := bits.Len(uint(nbInstances)) - 1
	for i := range inputs {
		if len(inputs[i]) != nbInstances {
			return nil, nil, fmt.Errorf("input %d nb instances expected %d got %d", i, nbInstances, len(inputs[i]))
		}
	}
	evalInput := make([][]*big.Int, nbInstances)
	// TODO: pad input to power of two
	for i := range evalInput {
		evalInput[i] = make(NativeMultilinear, nbInputs)
		for j := range evalInput[i] {
			evalInput[i][j] = new(big.Int).Set(inputs[j][i])
		}
	}
	evaluations = make([]*big.Int, nbInstances)
	for i := range evaluations {
		evaluations[i] = new(big.Int)
		evaluations[i] = gate.Evaluate(be, evalInput[i]...)
	}
	inputPreprocessors := make([]NativeMultilinear, nbInputs)
	for i := range inputs {
		inputPreprocessors[i] = make(NativeMultilinear, nbInstances)
		for j := range inputs[i] {
			inputPreprocessors[i][j] = new(big.Int).Set(inputs[i][j])
		}
	}
	for i := range evaluationPoints {
		if len(evaluationPoints[i]) != nbVars {
			return nil, nil, fmt.Errorf("nb evaluation points %d mismatch for claim %d", len(evaluationPoints), i)
		}
	}
	claimedEvaluations := make([]*big.Int, len(evaluationPoints))
	for i := range claimedEvaluations {
		claimedEvaluations[i] = eval(be, evaluations, evaluationPoints[i])
	}
	return &nativeGateClaim{
		engine:             be,
		gate:               gate,
		evaluationPoints:   evaluationPoints,
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
			aI = g.engine.Mul(aI, coeff)
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
			step.Set(s[j][i])
			operands[j].Set(s[j][block])
			step = g.engine.Sub(operands[j], step)
			for d := 1; d < degGJ; d++ {
				operands[d*nbInner+j] = g.engine.Add(operands[(d-1)*nbInner+j], step)
			}
		}
		_s := 0
		_e := nbInner
		for d := 0; d < degGJ; d++ {
			summand := new(big.Int)
			summand = g.gate.Evaluate(g.engine, operands[_s+1:_e]...)
			summand = g.engine.Mul(summand, operands[_s])
			res[d] = g.engine.Add(res[d], summand)
			_s, _e = _e, _e+nbInner
		}
	}
	for i := 0; i < degGJ; i++ {
		gJ[i] = g.engine.Add(gJ[i], res[i])
	}
	return gJ
}
