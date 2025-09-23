package gkr

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
)

// @tabaie TODO: Contains many things copy-pasted from gnark-crypto. Generify somehow?

// A SNARK gadget capable of verifying a GKR proof
// The goal is to prove/verify evaluations of many instances of the same circuit.

type Proof []sumcheckProof // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

// eqTimesGateEvalSumcheckLazyClaims is a lazy claim for sumcheck (verifier side).
// eqTimesGateEval is a polynomial consisting of ∑ᵢ cⁱ eq(-, xᵢ) w(-).
// Its purpose is to batch the checking of multiple evaluations of the same wire.
type eqTimesGateEvalSumcheckLazyClaims struct {
	wireI              int
	evaluationPoints   [][]frontend.Variable
	claimedEvaluations []frontend.Variable
	manager            *claimsManager // WARNING: Circular references
}

func (e *eqTimesGateEvalSumcheckLazyClaims) getWire() *gkrtypes.Wire {
	return e.manager.wires[e.wireI]
}

// verifyFinalEval finalizes the verification of w.
// The prover's claims w(xᵢ) = yᵢ have already been reduced to verifying
// ∑ cⁱ eq(xᵢ, r) w(r) = purportedValue. ( c is combinationCoeff )
// Both purportedValue and the vector r have been randomized during the sumcheck protocol.
// By taking the w term out of the sum we get the equivalent claim that
// for E := ∑ eq(xᵢ, r), it must be that E w(r) = purportedValue.
// If w is an input wire, the verifier can directly check its evaluation at r.
// Otherwise, the prover makes claims about the evaluation of w's input wires,
// wᵢ, at r, to be verified later.
// The claims are communicated through the proof parameter.
// The verifier checks here if the claimed evaluations of wᵢ(r) are consistent with
// the main claim, by checking E w(wᵢ(r)...) = purportedValue.
func (e *eqTimesGateEvalSumcheckLazyClaims) verifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff, purportedValue frontend.Variable, uniqueInputEvaluations []frontend.Variable) error {
	// the eq terms ( E )
	numClaims := len(e.evaluationPoints)
	evaluation := polynomial.EvalEq(api, e.evaluationPoints[numClaims-1], r)
	for i := numClaims - 2; i >= 0; i-- {
		evaluation = api.Mul(evaluation, combinationCoeff)
		eq := polynomial.EvalEq(api, e.evaluationPoints[i], r)
		evaluation = api.Add(evaluation, eq)
	}

	wire := e.getWire()

	// the g(...) term
	var gateEvaluation frontend.Variable
	if wire.IsInput() {
		gateEvaluation = e.manager.assignment[e.wireI].Evaluate(api, r)
	} else {

		injection, injectionLeftInv :=
			e.manager.wires.ClaimPropagationInfo(e.wireI)

		if len(injection) != len(uniqueInputEvaluations) {
			return fmt.Errorf("%d input wire evaluations given, %d expected", len(uniqueInputEvaluations), len(injection))
		}

		for uniqueI, i := range injection { // map from unique to all
			e.manager.add(wire.Inputs[i], r, uniqueInputEvaluations[uniqueI])
		}

		inputEvaluations := make([]frontend.Variable, len(wire.Inputs))
		for i, uniqueI := range injectionLeftInv { // map from all to unique
			inputEvaluations[i] = uniqueInputEvaluations[uniqueI]
		}

		gateEvaluation = wire.Gate.Evaluate(FrontendAPIWrapper{api}, inputEvaluations...)
	}
	evaluation = api.Mul(evaluation, gateEvaluation)

	api.AssertIsEqual(evaluation, purportedValue)
	return nil
}

func (e *eqTimesGateEvalSumcheckLazyClaims) claimsNum() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) varsNum() int {
	return len(e.evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaims) combinedSum(api frontend.API, a frontend.Variable) frontend.Variable {
	evalsAsPoly := polynomial.Polynomial(e.claimedEvaluations)
	return evalsAsPoly.Eval(api, a)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) degree(int) int {
	return 1 + e.getWire().Gate.Degree()
}

type claimsManager struct {
	claims     []*eqTimesGateEvalSumcheckLazyClaims
	assignment gkrtypes.WireAssignment
	wires      gkrtypes.Wires
}

func newClaimsManager(wires gkrtypes.Wires, assignment gkrtypes.WireAssignment) (claims claimsManager) {
	claims.assignment = assignment
	claims.claims = make([]*eqTimesGateEvalSumcheckLazyClaims, len(wires))
	claims.wires = wires

	for i := range wires {
		wire := wires[i]
		claims.claims[i] = &eqTimesGateEvalSumcheckLazyClaims{
			wireI:              i,
			evaluationPoints:   make([][]frontend.Variable, 0, wire.NbClaims()),
			claimedEvaluations: make(polynomial.Polynomial, wire.NbClaims()),
			manager:            &claims,
		}
	}
	return
}

func (m *claimsManager) add(wire int, evaluationPoint []frontend.Variable, evaluation frontend.Variable) {
	claim := m.claims[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

func (m *claimsManager) getLazyClaim(wire int) *eqTimesGateEvalSumcheckLazyClaims {
	return m.claims[wire]
}

func (m *claimsManager) deleteClaim(wire int) {
	m.claims[wire].manager = nil
	m.claims[wire] = nil
}

type settings struct {
	sorted           []*gkrtypes.Wire
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
}

type Option func(*settings)

func WithSortedCircuit(sorted []*gkrtypes.Wire) Option {
	return func(options *settings) {
		options.sorted = sorted
	}
}

func setup(api frontend.API, c gkrtypes.Circuit, assignment gkrtypes.WireAssignment, transcriptSettings fiatshamir.Settings, options ...Option) (settings, error) {
	var o settings
	var err error
	for _, option := range options {
		option(&o)
	}

	o.nbVars = assignment.NbVars()
	nbInstances := assignment.NbInstances()
	if 1<<o.nbVars != nbInstances {
		return o, errors.New("number of instances must be power of 2")
	}

	if o.sorted == nil {
		o.sorted = c.TopologicalSort()
	}

	if transcriptSettings.Transcript == nil {
		challengeNames := ChallengeNames(o.sorted, o.nbVars, transcriptSettings.Prefix)
		o.transcript = fiatshamir.NewTranscript(api, transcriptSettings.Hash, challengeNames)
		if err = o.transcript.Bind(challengeNames[0], transcriptSettings.BaseChallenges); err != nil {
			return o, err
		}
	} else {
		o.transcript, o.transcriptPrefix = transcriptSettings.Transcript, transcriptSettings.Prefix
	}

	return o, err
}

// ProofSize computes how large the proof for a circuit would be. It needs NbUniqueOutputs to be set
func ProofSize(c gkrtypes.Circuit, logNbInstances int) int {
	nbUniqueInputs := 0
	nbPartialEvalPolys := 0
	for i := range c {
		nbUniqueInputs += c[i].NbUniqueOutputs // each unique output is manifest in a finalEvalProof entry
		if !c[i].NoProof() {
			nbPartialEvalPolys += c[i].Gate.Degree() + 1
		}
	}
	return nbUniqueInputs + nbPartialEvalPolys*logNbInstances
}

func ChallengeNames(sorted []*gkrtypes.Wire, logNbInstances int, prefix string) []string {

	// Pre-compute the size TODO: Consider not doing this and just grow the list by appending
	size := logNbInstances // first challenge

	for _, w := range sorted {
		if w.NoProof() { // no proof, no challenge
			continue
		}
		if w.NbClaims() > 1 { //combine the claims
			size++
		}
		size += logNbInstances // full run of sumcheck on logNbInstances variables
	}

	nums := make([]string, max(len(sorted), logNbInstances))
	for i := range nums {
		nums[i] = strconv.Itoa(i)
	}

	challenges := make([]string, size)

	// output wire claims
	firstChallengePrefix := prefix + "fC."
	for j := 0; j < logNbInstances; j++ {
		challenges[j] = firstChallengePrefix + nums[j]
	}
	j := logNbInstances
	for i := len(sorted) - 1; i >= 0; i-- {
		if sorted[i].NoProof() {
			continue
		}
		wirePrefix := prefix + "w" + nums[i] + "."

		if sorted[i].NbClaims() > 1 {
			challenges[j] = wirePrefix + "comb"
			j++
		}

		partialSumPrefix := wirePrefix + "pSP."
		for k := 0; k < logNbInstances; k++ {
			challenges[j] = partialSumPrefix + nums[k]
			j++
		}
	}
	return challenges
}

func getFirstChallengeNames(logNbInstances int, prefix string) []string {
	res := make([]string, logNbInstances)
	firstChallengePrefix := prefix + "fC."
	for i := 0; i < logNbInstances; i++ {
		res[i] = firstChallengePrefix + strconv.Itoa(i)
	}
	return res
}

func getChallenges(transcript *fiatshamir.Transcript, names []string) (challenges []frontend.Variable, err error) {
	challenges = make([]frontend.Variable, len(names))
	for i, name := range names {
		if challenges[i], err = transcript.ComputeChallenge(name); err != nil {
			return
		}
	}
	return
}

// Verify the consistency of the claimed output with the claimed input
// Unlike in Prove, the assignment argument need not be complete
func Verify(api frontend.API, c gkrtypes.Circuit, assignment gkrtypes.WireAssignment, proof Proof, transcriptSettings fiatshamir.Settings, options ...Option) error {
	o, err := setup(api, c, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}

	claims := newClaimsManager(o.sorted, assignment)

	var firstChallenge []frontend.Variable
	firstChallenge, err = getChallenges(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return err
	}

	wirePrefix := o.transcriptPrefix + "w"
	var baseChallenge []frontend.Variable
	for i := len(c) - 1; i >= 0; i-- {
		wire := o.sorted[i]

		if wire.IsOutput() {
			claims.add(i, firstChallenge, assignment[i].Evaluate(api, firstChallenge))
		}

		proofW := proof[i]
		claim := claims.getLazyClaim(i)
		if wire.NoProof() { // input wires with one claim only
			// make sure the proof is empty
			if len(proofW.FinalEvalProof) != 0 || len(proofW.PartialSumPolys) != 0 {
				return errors.New("no proof allowed for input wire with a single claim")
			}

			if wire.NbClaims() == 1 { // input wire
				// simply evaluate and see if it matches
				evaluation := assignment[i].Evaluate(api, claim.evaluationPoints[0])
				api.AssertIsEqual(claim.claimedEvaluations[0], evaluation)
			}
		} else if err = verifySumcheck(
			api, claim, proof[i], fiatshamir.WithTranscript(o.transcript, wirePrefix+strconv.Itoa(i)+".", baseChallenge...),
		); err == nil {
			baseChallenge = proofW.FinalEvalProof
		} else {
			return err
		}
		claims.deleteClaim(i)
	}
	return nil
}

// TODO: Have this use algo_utils.TopologicalSort underneath

func (p Proof) Serialize() []frontend.Variable {
	size := 0
	for i := range p {
		for j := range p[i].PartialSumPolys {
			size += len(p[i].PartialSumPolys[j])
		}
		size += len(p[i].FinalEvalProof)
	}

	res := make([]frontend.Variable, 0, size)
	for i := range p {
		for j := range p[i].PartialSumPolys {
			res = append(res, p[i].PartialSumPolys[j]...)
		}
		res = append(res, p[i].FinalEvalProof...)
	}
	if len(res) != size {
		panic("bug") // TODO: Remove
	}
	return res
}

func computeLogNbInstances(wires []*gkrtypes.Wire, serializedProofLen int) int {
	partialEvalElemsPerVar := 0
	for _, w := range wires {
		if !w.NoProof() {
			partialEvalElemsPerVar += w.Gate.Degree() + 1
		}
		serializedProofLen -= w.NbUniqueOutputs
	}
	return serializedProofLen / partialEvalElemsPerVar
}

type variablesReader []frontend.Variable

func (r *variablesReader) nextN(n int) []frontend.Variable {
	res := (*r)[:n]
	*r = (*r)[n:]
	return res
}

func (r *variablesReader) hasNextN(n int) bool {
	return len(*r) >= n
}

func DeserializeProof(sorted []*gkrtypes.Wire, serializedProof []frontend.Variable) (Proof, error) {
	proof := make(Proof, len(sorted))
	logNbInstances := computeLogNbInstances(sorted, len(serializedProof))

	reader := variablesReader(serializedProof)
	for i, wI := range sorted {
		if !wI.NoProof() {
			proof[i].PartialSumPolys = make([]polynomial.Polynomial, logNbInstances)
			for j := range proof[i].PartialSumPolys {
				proof[i].PartialSumPolys[j] = reader.nextN(wI.Gate.Degree() + 1)
			}
		}
		proof[i].FinalEvalProof = reader.nextN(wI.NbUniqueInputs())
	}
	if reader.hasNextN(1) {
		return nil, fmt.Errorf("proof too long: expected %d encountered %d", len(serializedProof)-len(reader), len(serializedProof))
	}
	return proof, nil
}

type FrontendAPIWrapper struct {
	frontend.API
}

func (api FrontendAPIWrapper) Exp17(i frontend.Variable) frontend.Variable {
	res := api.Mul(i, i)    // i^2
	res = api.Mul(res, res) // i^4
	res = api.Mul(res, res) // i^8
	res = api.Mul(res, res) // i^16
	return api.Mul(res, i)  // i^17
}
