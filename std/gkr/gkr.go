package gkr

import (
	"crypto/rand"
	"errors"
	"fmt"
	bn254Gkr "github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark/std/gkr/internal"
	"strconv"
	"sync"

	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/std/sumcheck"
)

// @tabaie TODO: Contains many things copy-pasted from gnark-crypto. Generify somehow?

// The goal is to prove/verify evaluations of many instances of the same circuit

type GateFunction func(frontend.API, ...frontend.Variable) frontend.Variable

// A Gate is a low-degree multivariate polynomial
type Gate struct {
	Evaluate    GateFunction // Evaluate the polynomial function defining the gate
	nbIn        int          // number of inputs
	degree      int          // total degree of f
	solvableVar int          // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
}

// Degree returns the total degree of the gate's polynomial i.e. Degree(xy²) = 3
func (g *Gate) Degree() int {
	return g.degree
}

// SolvableVar returns the index of a variable of degree 1 in the gate's polynomial. If there is no such variable, it returns -1.
func (g *Gate) SolvableVar() int {
	return g.solvableVar
}

// NbIn returns the number of inputs to the gate (its fan-in)
func (g *Gate) NbIn() int {
	return g.nbIn
}

var (
	gates     = make(map[string]*Gate)
	gatesLock sync.Mutex
)

/*type registerGateSettings struct {
	solvableVar               int
	noSolvableVarVerification bool
	noDegreeVerification    bool
	degree                  int
}*/

// here options are not defined as functions on settings to make translation to their field counterpart easier
// TODO @Tabaie once GKR is moved to gnark, use the same options/settings type for all curves, obviating this

type registerGateOptionType byte

const (
	registerGateOptionTypeWithSolvableVar registerGateOptionType = iota
	registerGateOptionTypeWithUnverifiedSolvableVar
	registerGateOptionTypeWithNoSolvableVar
	registerGateOptionTypeWithUnverifiedDegree
	registerGateOptionTypeWithDegree
)

type registerGateOption struct {
	tp    registerGateOptionType
	param int
}

// WithSolvableVar gives the index of a variable of degree 1 in the gate's polynomial. RegisterGate will return an error if the given index is not correct.
func WithSolvableVar(linearVar int) *registerGateOption {
	return &registerGateOption{
		tp:    registerGateOptionTypeWithSolvableVar,
		param: linearVar,
	}
}

// WithUnverifiedSolvableVar sets the index of a variable of degree 1 in the gate's polynomial. RegisterGate will not verify that the given index is correct.
func WithUnverifiedSolvableVar(linearVar int) *registerGateOption {
	return &registerGateOption{
		tp:    registerGateOptionTypeWithUnverifiedSolvableVar,
		param: linearVar,
	}
}

// WithNoSolvableVar sets the gate as having no variable of degree 1. RegisterGate will not check the correctness of this claim.
func WithNoSolvableVar() *registerGateOption {
	return &registerGateOption{
		tp: registerGateOptionTypeWithNoSolvableVar,
	}
}

// WithUnverifiedDegree sets the degree of the gate. RegisterGate will not verify that the given degree is correct.
func WithUnverifiedDegree(degree int) *registerGateOption {
	return &registerGateOption{
		tp:    registerGateOptionTypeWithUnverifiedDegree,
		param: degree,
	}
}

// WithDegree sets the degree of the gate. RegisterGate will return an error if the degree is not correct.
func WithDegree(degree int) *registerGateOption {
	return &registerGateOption{
		tp:    registerGateOptionTypeWithDegree,
		param: degree,
	}
}

// RegisterGate creates a gate object and stores it in the gates registry
// name is a human-readable name for the gate
// f is the polynomial function defining the gate
// nbIn is the number of inputs to the gate
// NB! This package generally expects certain properties of the gate to be invariant across all curves.
// In particular the degree is computed and verified over BN254. If the leading coefficient is divided by
// the curve's order, the degree will be computed incorrectly.
func RegisterGate(name string, f GateFunction, nbIn int, options ...*registerGateOption) error {
	frF := internal.ToBn254GateFunction(f) // delegate tests to bn254
	var nameRand [4]byte
	if _, err := rand.Read(nameRand[:]); err != nil {
		return err
	}
	frName := fmt.Sprintf("%s-test-%x", name, nameRand)
	frOptions := make([]bn254Gkr.RegisterGateOption, 0, len(options))

	// translate options
	for _, opt := range options {
		switch opt.tp {
		case registerGateOptionTypeWithSolvableVar:
			frOptions = append(frOptions, bn254Gkr.WithSolvableVar(opt.param))
		case registerGateOptionTypeWithUnverifiedSolvableVar:
			frOptions = append(frOptions, bn254Gkr.WithUnverifiedSolvableVar(opt.param))
		case registerGateOptionTypeWithNoSolvableVar:
			frOptions = append(frOptions, bn254Gkr.WithNoSolvableVar())
		case registerGateOptionTypeWithUnverifiedDegree:
			frOptions = append(frOptions, bn254Gkr.WithUnverifiedDegree(opt.param))
		case registerGateOptionTypeWithDegree:
			frOptions = append(frOptions, bn254Gkr.WithDegree(opt.param))
		default:
			return fmt.Errorf("unknown option type %d", opt.tp)
		}
	}

	if err := bn254Gkr.RegisterGate(frName, frF, nbIn, frOptions...); err != nil {
		return err
	}
	bn254Gate := bn254Gkr.GetGate(frName)
	bn254Gkr.RemoveGate(frName)

	gatesLock.Lock()
	defer gatesLock.Unlock()

	gates[name] = &Gate{
		Evaluate:    f,
		nbIn:        nbIn,
		degree:      bn254Gate.Degree(),
		solvableVar: bn254Gate.SolvableVar(),
	}

	return nil
}

func GetGate(name string) *Gate {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	return gates[name]
}

func RemoveGate(name string) bool {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	_, found := gates[name]
	if found {
		delete(gates, name)
	}
	return found
}

type Wire struct {
	Gate            *Gate
	Inputs          []*Wire // if there are no Inputs, the wire is assumed an input wire
	nbUniqueOutputs int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

type Circuit []Wire

func (w Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w Wire) IsOutput() bool {
	return w.nbUniqueOutputs == 0
}

func (w Wire) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.nbUniqueOutputs
}

func (w Wire) nbUniqueInputs() int {
	set := make(map[*Wire]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

func (w Wire) noProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[*Wire]polynomial.MultiLin

type Proof []sumcheck.Proof // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wire
	evaluationPoints   [][]frontend.Variable
	claimedEvaluations []frontend.Variable
	manager            *claimsManager // WARNING: Circular references
}

func (e *eqTimesGateEvalSumcheckLazyClaims) VerifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff, purportedValue frontend.Variable, proof interface{}) error {
	inputEvaluationsNoRedundancy := proof.([]frontend.Variable)

	// the eq terms
	numClaims := len(e.evaluationPoints)
	evaluation := polynomial.EvalEq(api, e.evaluationPoints[numClaims-1], r)
	for i := numClaims - 2; i >= 0; i-- {
		evaluation = api.Mul(evaluation, combinationCoeff)
		eq := polynomial.EvalEq(api, e.evaluationPoints[i], r)
		evaluation = api.Add(evaluation, eq)
	}

	// the g(...) term
	var gateEvaluation frontend.Variable
	if e.wire.IsInput() {
		gateEvaluation = e.manager.assignment[e.wire].Evaluate(api, r)
	} else {
		inputEvaluations := make([]frontend.Variable, len(e.wire.Inputs))
		indexesInProof := make(map[*Wire]int, len(inputEvaluationsNoRedundancy))

		proofI := 0
		for inI, in := range e.wire.Inputs {
			indexInProof, found := indexesInProof[in]
			if !found {
				indexInProof = proofI
				indexesInProof[in] = indexInProof

				// defer verification, store new claim
				e.manager.add(in, r, inputEvaluationsNoRedundancy[indexInProof])
				proofI++
			}
			inputEvaluations[inI] = inputEvaluationsNoRedundancy[indexInProof]
		}
		if proofI != len(inputEvaluationsNoRedundancy) {
			return fmt.Errorf("%d input wire evaluations given, %d expected", len(inputEvaluationsNoRedundancy), proofI)
		}
		gateEvaluation = e.wire.Gate.Evaluate(api, inputEvaluations...)
	}
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
}

func newClaimsManager(c Circuit, assignment WireAssignment) (claims claimsManager) {
	claims.assignment = assignment
	claims.claimsMap = make(map[*Wire]*eqTimesGateEvalSumcheckLazyClaims, len(c))

	for i := range c {
		wire := &c[i]

		claims.claimsMap[wire] = &eqTimesGateEvalSumcheckLazyClaims{
			wire:               wire,
			evaluationPoints:   make([][]frontend.Variable, 0, wire.NbClaims()),
			claimedEvaluations: make(polynomial.Polynomial, wire.NbClaims()),
			manager:            &claims,
		}
	}
	return
}

func (m *claimsManager) add(wire *Wire, evaluationPoint []frontend.Variable, evaluation frontend.Variable) {
	claim := m.claimsMap[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

func (m *claimsManager) getLazyClaim(wire *Wire) *eqTimesGateEvalSumcheckLazyClaims {
	return m.claimsMap[wire]
}

func (m *claimsManager) deleteClaim(wire *Wire) {
	delete(m.claimsMap, wire)
}

type settings struct {
	sorted           []*Wire
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
}

type Option func(*settings)

func WithSortedCircuit(sorted []*Wire) Option {
	return func(options *settings) {
		options.sorted = sorted
	}
}

func setup(api frontend.API, c Circuit, assignment WireAssignment, transcriptSettings fiatshamir.Settings, options ...Option) (settings, error) {
	var o settings
	var err error
	for _, option := range options {
		option(&o)
	}

	o.nbVars = assignment.NumVars()
	nbInstances := assignment.NumInstances()
	if 1<<o.nbVars != nbInstances {
		return o, errors.New("number of instances must be power of 2")
	}

	if o.sorted == nil {
		o.sorted = topologicalSort(c)
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

// ProofSize computes how large the proof for a circuit would be. It needs nbUniqueOutputs to be set
func ProofSize(c Circuit, logNbInstances int) int {
	nbUniqueInputs := 0
	nbPartialEvalPolys := 0
	for i := range c {
		nbUniqueInputs += c[i].nbUniqueOutputs // each unique output is manifest in a finalEvalProof entry
		if !c[i].noProof() {
			nbPartialEvalPolys += c[i].Gate.Degree() + 1
		}
	}
	return nbUniqueInputs + nbPartialEvalPolys*logNbInstances
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ChallengeNames(sorted []*Wire, logNbInstances int, prefix string) []string {

	// Pre-compute the size TODO: Consider not doing this and just grow the list by appending
	size := logNbInstances // first challenge

	for _, w := range sorted {
		if w.noProof() { // no proof, no challenge
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
		if sorted[i].noProof() {
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
func Verify(api frontend.API, c Circuit, assignment WireAssignment, proof Proof, transcriptSettings fiatshamir.Settings, options ...Option) error {
	o, err := setup(api, c, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}

	claims := newClaimsManager(c, assignment)

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
			claims.add(wire, firstChallenge, assignment[wire].Evaluate(api, firstChallenge))
		}

		proofW := proof[i]
		finalEvalProof := proofW.FinalEvalProof.([]frontend.Variable)
		claim := claims.getLazyClaim(wire)
		if wire.noProof() { // input wires with one claim only
			// make sure the proof is empty
			if len(finalEvalProof) != 0 || len(proofW.PartialSumPolys) != 0 {
				return errors.New("no proof allowed for input wire with a single claim")
			}

			if wire.NbClaims() == 1 { // input wire
				// simply evaluate and see if it matches
				evaluation := assignment[wire].Evaluate(api, claim.evaluationPoints[0])
				api.AssertIsEqual(claim.claimedEvaluations[0], evaluation)
			}
		} else if err = sumcheck.Verify(
			api, claim, proof[i], fiatshamir.WithTranscript(o.transcript, wirePrefix+strconv.Itoa(i)+".", baseChallenge...),
		); err == nil {
			baseChallenge = finalEvalProof
		} else {
			return err
		}
		claims.deleteClaim(wire)
	}
	return nil
}

// outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsList(c Circuit, indexes map[*Wire]int) [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].nbUniqueOutputs = 0
		if c[i].IsInput() {
			c[i].Gate = GetGate("identity")
		}
	}
	ins := make(map[int]struct{}, len(c))
	for i := range c {
		for k := range ins { // clear map
			delete(ins, k)
		}
		for _, in := range c[i].Inputs {
			inI := indexes[in]
			res[inI] = append(res[inI], i)
			if _, ok := ins[inI]; !ok {
				in.nbUniqueOutputs++
				ins[inI] = struct{}{}
			}
		}
	}
	return res
}

type topSortData struct {
	outputs    [][]int
	status     []int // status > 0 indicates number of inputs left to be ready. status = 0 means ready. status = -1 means done
	index      map[*Wire]int
	leastReady int
}

func (d *topSortData) markDone(i int) {

	d.status[i] = -1

	for _, outI := range d.outputs[i] {
		d.status[outI]--
		if d.status[outI] == 0 && outI < d.leastReady {
			d.leastReady = outI
		}
	}

	for d.leastReady < len(d.status) && d.status[d.leastReady] != 0 {
		d.leastReady++
	}
}

func indexMap(c Circuit) map[*Wire]int {
	res := make(map[*Wire]int, len(c))
	for i := range c {
		res[&c[i]] = i
	}
	return res
}

func statusList(c Circuit) []int {
	res := make([]int, len(c))
	for i := range c {
		res[i] = len(c[i].Inputs)
	}
	return res
}

// TODO: Have this use algo_utils.TopologicalSort underneath

// topologicalSort sorts the wires in order of dependence. Such that for any wire, any one it depends on
// occurs before it. It tries to stick to the input order as much as possible. An already sorted list will remain unchanged.
// It also sets the nbOutput flags, and a dummy IdentityGate for input wires.
// Worst-case inefficient O(n^2), but that probably won't matter since the circuits are small.
// Furthermore, it is efficient with already-close-to-sorted lists, which are the expected input
func topologicalSort(c Circuit) []*Wire {
	var data topSortData
	data.index = indexMap(c)
	data.outputs = outputsList(c, data.index)
	data.status = statusList(c)
	sorted := make([]*Wire, len(c))

	for data.leastReady = 0; data.status[data.leastReady] != 0; data.leastReady++ {
	}

	for i := range c {
		sorted[i] = &c[data.leastReady]
		data.markDone(data.leastReady)
	}

	return sorted
}

func (a WireAssignment) NumInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignment) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

func (p Proof) Serialize() []frontend.Variable {
	size := 0
	for i := range p {
		for j := range p[i].PartialSumPolys {
			size += len(p[i].PartialSumPolys[j])
		}
		size += len(p[i].FinalEvalProof.([]frontend.Variable))
	}

	res := make([]frontend.Variable, 0, size)
	for i := range p {
		for j := range p[i].PartialSumPolys {
			res = append(res, p[i].PartialSumPolys[j]...)
		}
		res = append(res, p[i].FinalEvalProof.([]frontend.Variable)...)
	}
	if len(res) != size {
		panic("bug") // TODO: Remove
	}
	return res
}

func computeLogNbInstances(wires []*Wire, serializedProofLen int) int {
	partialEvalElemsPerVar := 0
	for _, w := range wires {
		if !w.noProof() {
			partialEvalElemsPerVar += w.Gate.Degree() + 1
		}
		serializedProofLen -= w.nbUniqueOutputs
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

func DeserializeProof(sorted []*Wire, serializedProof []frontend.Variable) (Proof, error) {
	proof := make(Proof, len(sorted))
	logNbInstances := computeLogNbInstances(sorted, len(serializedProof))

	reader := variablesReader(serializedProof)
	for i, wI := range sorted {
		if !wI.noProof() {
			proof[i].PartialSumPolys = make([]polynomial.Polynomial, logNbInstances)
			for j := range proof[i].PartialSumPolys {
				proof[i].PartialSumPolys[j] = reader.nextN(wI.Gate.Degree() + 1)
			}
		}
		proof[i].FinalEvalProof = reader.nextN(wI.nbUniqueInputs())
	}
	if reader.hasNextN(1) {
		return nil, fmt.Errorf("proof too long: expected %d encountered %d", len(serializedProof)-len(reader), len(serializedProof))
	}
	return proof, nil
}

func init() {
	panicIfError(RegisterGate("mul2", func(api frontend.API, x ...frontend.Variable) frontend.Variable {
		return api.Mul(x[0], x[1])
	}, 2, WithUnverifiedDegree(2), WithNoSolvableVar()))
	panicIfError(RegisterGate("add2", func(api frontend.API, x ...frontend.Variable) frontend.Variable {
		return api.Add(x[0], x[1])
	}, 2, WithUnverifiedDegree(1), WithUnverifiedSolvableVar(0)))
	panicIfError(RegisterGate("identity", func(api frontend.API, x ...frontend.Variable) frontend.Variable {
		return x[0]
	}, 1, WithUnverifiedDegree(1), WithUnverifiedSolvableVar(0)))
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
