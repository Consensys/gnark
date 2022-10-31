package gkr

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/std/sumcheck"
)

// TODO: Contains many things copy-pasted from gnark-crypto. Generify somehow?

type Gate interface {
	Evaluate(frontend.API, ...frontend.Variable) frontend.Variable
	Degree() int
}

type Wire struct {
	Gate       Gate
	Inputs     []*Wire // if there are no Inputs, the wire is assumed an input wire
	NumOutputs int     // number of other wires using it as input, not counting doubles (i.e. providing two inputs to the same gate counts as one). By convention, equal to 1 for output wires
}

type CircuitLayer []Wire

func (l CircuitLayer) References() []*Wire {
	res := make([]*Wire, len(l))

	for i := range l {
		res[i] = &l[i]
	}

	return res
}

// TODO: Constructor so that user doesn't have to give layers explicitly.
type Circuit []CircuitLayer

func (w *Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (c Circuit) Size() int { //TODO: Worth caching?
	res := len(c[0])
	for i := range c {
		res += len(c[i])
	}
	return res
}

func (c Circuit) InputLayer() []*Wire {
	return c[len(c)-1].References()
}

func (c Circuit) OutputLayer() []*Wire {
	return c[0].References()
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[*Wire]polynomial.MultiLin

type Proof [][]sumcheck.Proof // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wire
	evaluationPoints   [][]frontend.Variable
	claimedEvaluations []frontend.Variable
	manager            *claimsManager // WARNING: Circular references
}

func (e *eqTimesGateEvalSumcheckLazyClaims) VerifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff, purportedValue frontend.Variable, proof interface{}) error {
	inputEvaluations := proof.([]frontend.Variable)

	// defer verification, store the new claims
	e.manager.addForInput(e.wire, r, inputEvaluations)

	numClaims := len(e.evaluationPoints)

	evaluation := polynomial.EvalEq(api, e.evaluationPoints[numClaims-1], r)
	for i := numClaims - 2; i >= 0; i-- {
		evaluation = api.Mul(evaluation, combinationCoeff)
		eq := polynomial.EvalEq(api, e.evaluationPoints[i], r)
		evaluation = api.Add(evaluation, eq)
	}

	if expected, given := len(e.wire.Inputs), len(inputEvaluations); expected != given {
		return fmt.Errorf("malformed proof: wire has %d inputs, but %d input evaluations given", expected, given)
	}
	gateEvaluation := e.wire.Gate.Evaluate(api, inputEvaluations...)
	evaluation = api.Mul(evaluation, gateEvaluation)

	api.AssertIsEqual(evaluation, purportedValue)
	return nil
}

func (e *eqTimesGateEvalSumcheckLazyClaims) ClaimsNum() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) VarsNum() int {
	return len(e.evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaims) CombinedSum(api frontend.API, a frontend.Variable) frontend.Variable {
	evalsAsPoly := polynomial.Polynomial(e.claimedEvaluations)
	return evalsAsPoly.Eval(api, a)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) Degree(int) int {
	return 1 + e.wire.Gate.Degree()
}

type claimsManager struct {
	claimsMap  map[*Wire]*eqTimesGateEvalSumcheckLazyClaims
	assignment WireAssignment
	numClaims  int
}

func newClaimsManager(c Circuit, assignment WireAssignment) (claims claimsManager) {
	claims.assignment = assignment
	claims.claimsMap = make(map[*Wire]*eqTimesGateEvalSumcheckLazyClaims, c.Size())

	for _, layer := range c {
		for i := 0; i < len(layer); i++ {
			wire := &layer[i]

			claims.claimsMap[wire] = &eqTimesGateEvalSumcheckLazyClaims{
				wire:               wire,
				evaluationPoints:   make([][]frontend.Variable, 0, wire.NumOutputs),
				claimedEvaluations: make(polynomial.Polynomial, wire.NumOutputs),
				manager:            &claims,
			}
		}
	}
	return
}

func (m *claimsManager) add(wire *Wire, evaluationPoint []frontend.Variable, evaluation frontend.Variable) {
	m.numClaims++
	if m.numClaims%claimsPerLog == 0 {
		//fmt.Println("GKR:", m.numClaims, "total claims")
	}
	if wire.IsInput() {
		wire.Gate = identityGate{}
	}
	claim := m.claimsMap[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

// addForInput claims regarding all inputs to the wire, all evaluated at the same point
func (m *claimsManager) addForInput(wire *Wire, evaluationPoint []frontend.Variable, evaluations []frontend.Variable) {
	wiresWithClaims := make(map[*Wire]struct{}) // In case the gate takes the same wire as input multiple times, one claim would suffice

	for inputI, inputWire := range wire.Inputs {
		if _, found := wiresWithClaims[inputWire]; !found { //skip repeated claims
			wiresWithClaims[inputWire] = struct{}{}
			m.add(inputWire, evaluationPoint, evaluations[inputI])
		}
	}
}

func (m *claimsManager) getLazyClaim(wire *Wire) *eqTimesGateEvalSumcheckLazyClaims {

	return m.claimsMap[wire]
}

const claimsPerLog = 2

func (m *claimsManager) deleteClaim(wire *Wire) {
	m.numClaims--
	delete(m.claimsMap, wire)
}

// Verify the consistency of the claimed output with the claimed input
// Unlike in Prove, the assignment argument need not be complete
func Verify(api frontend.API, c Circuit, assignment WireAssignment, proof Proof, transcript sumcheck.ArithmeticTranscript) error {
	claims := newClaimsManager(c, assignment)

	outLayer := c[0]

	firstChallenge := transcript.NextN(api, assignment[&outLayer[0]].NumVars()) //TODO: Clean way to extract numVars
	//fmt.Print("first challenge:")
	//api.Println(firstChallenge)

	for i := range outLayer {
		wire := &outLayer[i]
		claims.add(wire, firstChallenge, assignment[wire].Eval(api, firstChallenge))
	}

	for layerI, layer := range c {

		for wireI := range layer {
			wire := &layer[wireI]
			claim := claims.getLazyClaim(wire)
			wProof := proof[layerI][wireI] // proof corresponding to this wire
			if claim.ClaimsNum() == 1 && wire.IsInput() {
				// simply evaluate and see if it matches
				if wProof.FinalEvalProof != nil {
					return fmt.Errorf("malformed proof: input node should have no final evaluation proof")
				}
				evaluation := assignment[wire].Eval(api, claim.evaluationPoints[0])
				api.AssertIsEqual(claim.claimedEvaluations[0], evaluation)

			} else {
				//fmt.Println(layerI)
				if err := sumcheck.Verify(api, claim, wProof, transcript); err != nil {
					return err
				}
			}
			claims.deleteClaim(wire)
		}
	}
	return nil
}

type identityGate struct{}

func (identityGate) Evaluate(_ frontend.API, input ...frontend.Variable) frontend.Variable {
	return input[0]
}

func (identityGate) Degree() int {
	return 1
}
