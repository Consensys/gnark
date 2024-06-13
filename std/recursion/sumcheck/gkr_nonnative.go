package sumcheck

import (
	"fmt"
	"slices"
	"strconv"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark-crypto/utils"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
	polynative "github.com/consensys/gnark/std/polynomial"
)

// @tabaie TODO: Contains many things copy-pasted from gnark-crypto. Generify somehow?

// The goal is to prove/verify evaluations of many instances of the same circuit

// type gateinput struct {
// 	api arithEngine
// 	element ...emulated.Element
// }

// Gate must be a low-degree polynomial
type Gate interface {
	Evaluate(...frontend.Variable) frontend.Variable // removed api ?
	Degree() int
}

type Wire struct {
	Gate            Gate
	Inputs          []*Wire // if there are no Inputs, the wire is assumed an input wire
	nbUniqueOutputs int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

// Gate must be a low-degree polynomial
type GateFr[FR emulated.FieldParams] interface {
	Evaluate(emuEngine[FR], ...emulated.Element[FR]) emulated.Element[FR] // removed api ?
	Degree() int
}

type WireFr[FR emulated.FieldParams] struct {
	Gate            GateFr[FR]
	Inputs          []*WireFr[FR] // if there are no Inputs, the wire is assumed an input wire
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

func (c Circuit) maxGateDegree() int {
	res := 1
	for i := range c {
		if !c[i].IsInput() {
			res = utils.Max(res, c[i].Gate.Degree())
		}
	}
	return res
}

type CircuitFr[FR emulated.FieldParams] []WireFr[FR]

func (w WireFr[FR]) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w WireFr[FR]) IsOutput() bool {
	return w.nbUniqueOutputs == 0
}

func (w WireFr[FR]) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.nbUniqueOutputs
}

func (w WireFr[FR]) nbUniqueInputs() int {
	set := make(map[*WireFr[FR]]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

func (w WireFr[FR]) noProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[*Wire]polynative.MultiLin

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignmentFr[FR emulated.FieldParams] map[*WireFr[FR]]polynomial.Multilinear[FR]

type Proofs[FR emulated.FieldParams] []nonNativeProofGKR[FR] // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

type eqTimesGateEvalSumcheckLazyClaimsFr[FR emulated.FieldParams] struct {
	wire               *WireFr[FR]
	evaluationPoints   [][]emulated.Element[FR]
	claimedEvaluations []emulated.Element[FR]
	manager            *claimsManagerFr[FR] // WARNING: Circular references
	verifier           *GKRVerifier[FR]
}

func (e *eqTimesGateEvalSumcheckLazyClaimsFr[FR]) VerifyFinalEval(r []emulated.Element[FR], combinationCoeff, purportedValue emulated.Element[FR], proof EvaluationProofFr[FR]) error {
	inputEvaluationsNoRedundancy := proof

	p, err := polynomial.New[FR](e.verifier.api)
	if err != nil {
		return err
	}

	// the eq terms
	numClaims := len(e.evaluationPoints)
	evaluation := p.EvalEqual(polynomial.FromSlice(e.evaluationPoints[numClaims-1]), polynomial.FromSlice(r))
	for i := numClaims - 2; i >= 0; i-- {
		evaluation = p.Mul(evaluation, &combinationCoeff)
		eq := p.EvalEqual(polynomial.FromSlice(e.evaluationPoints[i]), polynomial.FromSlice(r))
		evaluation = p.Add(evaluation, eq)	
	}

	// the g(...) term
	var gateEvaluation emulated.Element[FR]
	if e.wire.IsInput() {
		gateEvaluationPtr, err := p.EvalMultilinear(polynomial.FromSlice(r), e.manager.assignment[e.wire])
		if err != nil {
			return err
		}
		gateEvaluation = *gateEvaluationPtr
	} else {
		inputEvaluations := make([]emulated.Element[FR], len(e.wire.Inputs))
		indexesInProof := make(map[*WireFr[FR]]int, len(inputEvaluationsNoRedundancy))

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
		gateEvaluation = e.wire.Gate.Evaluate(e.verifier.engine, inputEvaluations...)
	}
	evaluation = p.Mul(evaluation, &gateEvaluation)

	p.AssertIsEqual(evaluation, &purportedValue)
	return nil
}

func (e *eqTimesGateEvalSumcheckLazyClaimsFr[FR]) NbClaims() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaimsFr[FR]) NbVars() int {
	return len(e.evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaimsFr[FR]) CombinedSum(a *emulated.Element[FR]) *emulated.Element[FR] {
	evalsAsPoly := polynomial.Univariate[FR](e.claimedEvaluations)
	return e.verifier.p.EvalUnivariate(evalsAsPoly, a)
}

func (e *eqTimesGateEvalSumcheckLazyClaimsFr[FR]) Degree(int) int {
	return 1 + e.wire.Gate.Degree()
}

func (e *eqTimesGateEvalSumcheckLazyClaimsFr[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff, expectedValue *emulated.Element[FR], proof EvaluationProofFr[FR]) error {
	val, err := e.verifier.p.EvalMultilinear(r, e.manager.assignment[e.wire])
	if err != nil {
		return fmt.Errorf("evaluation error: %w", err)
	}
	e.verifier.p.AssertIsEqual(val, expectedValue)
	return nil
}


type claimsManagerFr[FR emulated.FieldParams] struct {
	claimsMap  map[*WireFr[FR]]*eqTimesGateEvalSumcheckLazyClaimsFr[FR]
	assignment WireAssignmentFr[FR]
}

func newClaimsManagerFr[FR emulated.FieldParams](c CircuitFr[FR], assignment WireAssignmentFr[FR], verifier GKRVerifier[FR]) (claims claimsManagerFr[FR]) {
	claims.assignment = assignment
	claims.claimsMap = make(map[*WireFr[FR]]*eqTimesGateEvalSumcheckLazyClaimsFr[FR], len(c))

	for i := range c {
		wire := &c[i]

		claims.claimsMap[wire] = &eqTimesGateEvalSumcheckLazyClaimsFr[FR]{
			wire:               wire,
			evaluationPoints:   make([][]emulated.Element[FR], 0, wire.NbClaims()),
			claimedEvaluations: make(polynomial.Multilinear[FR], wire.NbClaims()),
			manager:            &claims,
			verifier:           &verifier,
		}
	}
	return
}

func (m *claimsManagerFr[FR]) add(wire *WireFr[FR], evaluationPoint []emulated.Element[FR], evaluation emulated.Element[FR]) {
	claim := m.claimsMap[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

func (m *claimsManagerFr[FR]) getLazyClaim(wire *WireFr[FR]) *eqTimesGateEvalSumcheckLazyClaimsFr[FR] {
	return m.claimsMap[wire]
}

func (m *claimsManagerFr[FR]) deleteClaim(wire *WireFr[FR]) {
	delete(m.claimsMap, wire)
}

type claimsManager struct {
	claimsMap  map[*Wire]*eqTimesGateEvalSumcheckLazyClaims
	assignment WireAssignment
	memPool    *polynative.Pool
	workers    *utils.WorkerPool
}

func newClaimsManager(c Circuit, assignment WireAssignment, o settings) (claims claimsManager) {
	claims.assignment = assignment
	claims.claimsMap = make(map[*Wire]*eqTimesGateEvalSumcheckLazyClaims, len(c))
	claims.memPool = o.pool
	claims.workers = o.workers

	for i := range c {
		wire := &c[i]

		claims.claimsMap[wire] = &eqTimesGateEvalSumcheckLazyClaims{
			wire:               wire,
			evaluationPoints:   make([][]frontend.Variable, 0, wire.NbClaims()),
			claimedEvaluations: make([]frontend.Variable, wire.NbClaims()),
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

func (m *claimsManager) getClaim(wire *Wire) *eqTimesGateEvalSumcheckClaims {
	lazy := m.claimsMap[wire]
	res := &eqTimesGateEvalSumcheckClaims{
		wire:               wire,
		evaluationPoints:   lazy.evaluationPoints,
		claimedEvaluations: lazy.claimedEvaluations,
		manager:            m,
	}

	if wire.IsInput() {
		res.inputPreprocessors = []polynative.MultiLin{m.memPool.Clone(m.assignment[wire])}
	} else {
		res.inputPreprocessors = make([]polynative.MultiLin, len(wire.Inputs))

		for inputI, inputW := range wire.Inputs {
			res.inputPreprocessors[inputI] = m.memPool.Clone(m.assignment[inputW]) //will be edited later, so must be deep copied
		}
	}
	return res
}

func (m *claimsManager) deleteClaim(wire *Wire) {
	delete(m.claimsMap, wire)
}

type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wire
	evaluationPoints   [][]frontend.Variable // x in the paper
	claimedEvaluations []frontend.Variable   // y in the paper
	manager            *claimsManager
}

type eqTimesGateEvalSumcheckClaims struct {
	wire               *Wire
	evaluationPoints   [][]frontend.Variable // x in the paper
	claimedEvaluations []frontend.Variable   // y in the paper
	manager            *claimsManager

	inputPreprocessors []polynative.MultiLin // P_u in the paper, so that we don't need to pass along all the circuit's evaluations

	eq polynative.MultiLin // ∑_i τ_i eq(x_i, -)
}

func (e *eqTimesGateEvalSumcheckClaims) NbClaims() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckClaims) NbVars() int {
	return len(e.evaluationPoints[0])
}

func (c *eqTimesGateEvalSumcheckClaims) Combine(api frontend.API, combinationCoeff *frontend.Variable) polynative.Polynomial {
	varsNum := c.NbVars()
	eqLength := 1 << varsNum
	claimsNum := c.NbClaims()
	// initialize the eq tables
	c.eq = c.manager.memPool.Make(eqLength)

	c.eq[0] = frontend.Variable(1)
	c.eq.Eq(api, c.evaluationPoints[0])

	newEq := polynative.MultiLin(c.manager.memPool.Make(eqLength))
	aI := combinationCoeff

	for k := 1; k < claimsNum; k++ { // TODO: parallelizable?
		// define eq_k = aᵏ eq(x_k1, ..., x_kn, *, ..., *) where x_ki are the evaluation points
		frontend.Set(&newEq[0], &aI)

		c.eqAcc(api, c.eq, newEq, c.evaluationPoints[k])

		// newEq.Eq(c.evaluationPoints[k])
		// eqAsPoly := polynomial.Polynomial(c.eq) //just semantics
		// eqAsPoly.Add(eqAsPoly, polynomial.Polynomial(newEq))

		if k+1 < claimsNum {
			api.Mul(&aI, &combinationCoeff)
		}
	}

	c.manager.memPool.Dump(newEq)

	// from this point on the claim is a rather simple one: g = E(h) × R_v (P_u0(h), ...) where E and the P_u are multilinear and R_v is of low-degree

	return c.computeGJ(api)
}

// eqAcc sets m to an eq table at q and then adds it to e
func (c *eqTimesGateEvalSumcheckClaims) eqAcc(api frontend.API, e, m polynative.MultiLin, q []frontend.Variable) {
	n := len(q)

	//At the end of each iteration, m(h₁, ..., hₙ) = Eq(q₁, ..., qᵢ₊₁, h₁, ..., hᵢ₊₁)
	for i := range q { // In the comments we use a 1-based index so q[i] = qᵢ₊₁
		// go through all assignments of (b₁, ..., bᵢ) ∈ {0,1}ⁱ
		const threshold = 1 << 6
		k := 1 << i
		if k < threshold {
			for j := 0; j < k; j++ {
				j0 := j << (n - i)    // bᵢ₊₁ = 0
				j1 := j0 + 1<<(n-1-i) // bᵢ₊₁ = 1

				m[j1] = api.Mul(&q[i], &m[j0])  // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) qᵢ₊₁
				m[j0] = api.Sub(&m[j0], &m[j1]) // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) (1-qᵢ₊₁)
			}
		} else {
			c.manager.workers.Submit(k, func(start, end int) {
				for j := start; j < end; j++ {
					j0 := j << (n - i)    // bᵢ₊₁ = 0
					j1 := j0 + 1<<(n-1-i) // bᵢ₊₁ = 1

					m[j1] = api.Mul(&q[i], &m[j0])  // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) qᵢ₊₁
					m[j0] = api.Sub(&m[j0], &m[j1]) // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) (1-qᵢ₊₁)
				}
			}, 1024).Wait()
		}

	}
	c.manager.workers.Submit(len(e), func(start, end int) {
		for i := start; i < end; i++ {
			e[i] = api.Add(&e[i], &m[i])
		}
	}, 512).Wait()

	// e.Add(e, polynomial.Polynomial(m))
}

// computeGJ: gⱼ = ∑_{0≤i<2ⁿ⁻ʲ} g(r₁, r₂, ..., rⱼ₋₁, Xⱼ, i...) = ∑_{0≤i<2ⁿ⁻ʲ} E(r₁, ..., X_j, i...) R_v( P_u0(r₁, ..., X_j, i...), ... ) where  E = ∑ eq_k
// the polynomial is represented by the evaluations g_j(1), g_j(2), ..., g_j(deg(g_j)).
// The value g_j(0) is inferred from the equation g_j(0) + g_j(1) = gⱼ₋₁(rⱼ₋₁). By convention, g₀ is a constant polynomial equal to the claimed sum.
func (c *eqTimesGateEvalSumcheckClaims) computeGJ(api frontend.API) polynative.Polynomial {

	degGJ := 1 + c.wire.Gate.Degree() // guaranteed to be no smaller than the actual deg(g_j)
	nbGateIn := len(c.inputPreprocessors)

	// Let f ∈ { E(r₁, ..., X_j, d...) } ∪ {P_ul(r₁, ..., X_j, d...) }. It is linear in X_j, so f(m) = m×(f(1) - f(0)) + f(0), and f(0), f(1) are easily computed from the bookkeeping tables
	s := make([]polynative.MultiLin, nbGateIn+1)
	s[0] = c.eq
	copy(s[1:], c.inputPreprocessors)

	// Perf-TODO: Collate once at claim "combination" time and not again. then, even folding can be done in one operation every time "next" is called
	nbInner := len(s) // wrt output, which has high nbOuter and low nbInner
	nbOuter := len(s[0]) / 2

	gJ := make([]frontend.Variable, degGJ)
	var mu sync.Mutex
	computeAll := func(start, end int) {
		var step frontend.Variable

		res := make([]frontend.Variable, degGJ)
		operands := make([]frontend.Variable, degGJ*nbInner)

		for i := start; i < end; i++ {

			block := nbOuter + i
			for j := 0; j < nbInner; j++ {
				frontend.Set(step, s[j][i])
				frontend.Set(operands[j], s[j][block])
				step = api.Sub(&operands[j], &step)
				for d := 1; d < degGJ; d++ {
					operands[d*nbInner+j] = api.Add(&operands[(d-1)*nbInner+j], &step)
				}
			}

			_s := 0
			_e := nbInner
			for d := 0; d < degGJ; d++ {
				summand := c.wire.Gate.Evaluate(operands[_s+1 : _e]...)
				summand = api.Mul(&summand, &operands[_s])
				res[d] = api.Add(&res[d], &summand)
				_s, _e = _e, _e+nbInner
			}
		}
		mu.Lock()
		for i := 0; i < len(gJ); i++ {
			gJ[i] = api.Add(&gJ[i], &res[i])
		}
		mu.Unlock()
	}

	const minBlockSize = 64

	if nbOuter < minBlockSize {
		// no parallelization
		computeAll(0, nbOuter)
	} else {
		c.manager.workers.Submit(nbOuter, computeAll, minBlockSize).Wait()
	}

	// Perf-TODO: Separate functions Gate.TotalDegree and Gate.Degree(i) so that we get to use possibly smaller values for degGJ. Won't help with MiMC though

	return gJ
}

// Next first folds the "preprocessing" and "eq" polynomials then compute the new g_j
func (c *eqTimesGateEvalSumcheckClaims) Next(api frontend.API, element *frontend.Variable) polynative.Polynomial {
	const minBlockSize = 512
	n := len(c.eq) / 2
	if n < minBlockSize {
		// no parallelization
		for i := 0; i < len(c.inputPreprocessors); i++ {
			c.inputPreprocessors[i].Fold(api, element)
		}
		c.eq.Fold(api, element)
	} else {
		wgs := make([]*sync.WaitGroup, len(c.inputPreprocessors))
		for i := 0; i < len(c.inputPreprocessors); i++ {
			wgs[i] = c.manager.workers.Submit(n, c.inputPreprocessors[i].FoldParallel(api, element), minBlockSize)
		}
		c.manager.workers.Submit(n, c.eq.FoldParallel(api, element), minBlockSize).Wait()
		for _, wg := range wgs {
			wg.Wait()
		}
	}

	return c.computeGJ(api)
}

func (c *eqTimesGateEvalSumcheckClaims) ProverFinalEval(api frontend.API, r []frontend.Variable) nativeEvaluationProof {

	//defer the proof, return list of claims
	evaluations := make([]frontend.Variable, 0, len(c.wire.Inputs))
	noMoreClaimsAllowed := make(map[*Wire]struct{}, len(c.inputPreprocessors))
	noMoreClaimsAllowed[c.wire] = struct{}{}

	for inI, in := range c.wire.Inputs {
		puI := c.inputPreprocessors[inI]
		if _, found := noMoreClaimsAllowed[in]; !found {
			noMoreClaimsAllowed[in] = struct{}{}
			puI.Fold(api, r[len(r)-1])
			c.manager.add(in, r, puI[0])
			evaluations = append(evaluations, puI[0])
		}
		c.manager.memPool.Dump(puI)
	}

	c.manager.memPool.Dump(c.claimedEvaluations, c.eq)

	return evaluations
}

func (e *eqTimesGateEvalSumcheckClaims) Degree(int) int {
	return 1 + e.wire.Gate.Degree()
}

func setup(api frontend.API, c Circuit, assignment WireAssignment, transcriptSettings fiatshamir.Settings, options ...OptionGkr) (settings, error) {
	var o settings
	var err error
	for _, option := range options {
		option(&o)
	}

	o.nbVars = assignment.NumVars()
	nbInstances := assignment.NumInstances()
	if 1<<o.nbVars != nbInstances {
		return o, fmt.Errorf("number of instances must be power of 2")
	}

	if o.pool == nil {
		pool := polynative.NewPool(c.MemoryRequirements(nbInstances)...)
		o.pool = &pool
	}

	if o.workers == nil {
		o.workers = utils.NewWorkerPool()
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

type settings struct {
	pool             *polynative.Pool
	sorted           []*Wire
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
	workers          *utils.WorkerPool
}

type OptionSet func(*settings)

func WithPool(pool *polynative.Pool) OptionSet {
	return func(options *settings) {
		options.pool = pool
	}
}

func WithSortedCircuitSet(sorted []*Wire) OptionSet {
	return func(options *settings) {
		options.sorted = sorted
	}
}

func WithWorkers(workers *utils.WorkerPool) OptionSet {
	return func(options *settings) {
		options.workers = workers
	}
}

// MemoryRequirements returns an increasing vector of memory allocation sizes required for proving a GKR statement
func (c Circuit) MemoryRequirements(nbInstances int) []int {
	res := []int{256, nbInstances, nbInstances * (c.maxGateDegree() + 1)}

	if res[0] > res[1] { // make sure it's sorted
		res[0], res[1] = res[1], res[0]
		if res[1] > res[2] {
			res[1], res[2] = res[2], res[1]
		}
	}

	return res
}

type ProofGkr []nativeProofGKR

type OptionGkr func(*settings)

type settingsFr[FR emulated.FieldParams] struct {
	sorted           []*WireFr[FR]
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
}

type OptionFr[FR emulated.FieldParams] func(*settingsFr[FR])

func WithSortedCircuit[FR emulated.FieldParams](sorted []*WireFr[FR]) OptionFr[FR] {
	return func(options *settingsFr[FR]) {
		options.sorted = sorted
	}
}

// Verifier allows to check sumcheck proofs. See [NewVerifier] for initializing the instance.
type GKRVerifier[FR emulated.FieldParams] struct {
	api frontend.API
	engine emuEngine[FR]
	f   *emulated.Field[FR]
	p   *polynomial.Polynomial[FR]
	*config
}

// NewVerifier initializes a new sumcheck verifier for the parametric emulated
// field FR. It returns an error if the given options are invalid or when
// initializing emulated arithmetic fails.
func NewGKRVerifier[FR emulated.FieldParams](api frontend.API, opts ...Option) (*GKRVerifier[FR], error) {
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new configuration: %w", err)
	}
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	return &GKRVerifier[FR]{
		api:    api,
		f:      f,
		p:      p,
		config: cfg,
	}, nil
}

// bindChallenge binds the values for challengeName using in-circuit Fiat-Shamir transcript.
func (v *GKRVerifier[FR]) bindChallenge(fs *fiatshamir.Transcript, challengeName string, values []emulated.Element[FR]) error {
	for i := range values {
		bts := v.f.ToBits(&values[i])
		slices.Reverse(bts)
		if err := fs.Bind(challengeName, bts); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

func (v *GKRVerifier[FR]) setup(api frontend.API, c CircuitFr[FR], assignment WireAssignmentFr[FR], transcriptSettings fiatshamir.SettingsFr[FR], options ...OptionFr[FR]) (settingsFr[FR], error) {
	var fr FR
	var o settingsFr[FR]
	var err error
	for _, option := range options {
		option(&o)
	}

	cfg, err := newVerificationConfig[FR]()
	if err != nil {
		return o, fmt.Errorf("verification opts: %w", err)
	}

	o.nbVars = assignment.NumVars()
	nbInstances := assignment.NumInstances()
	if 1<<o.nbVars != nbInstances {
		return o, fmt.Errorf("number of instances must be power of 2")
	}

	if o.sorted == nil {
		o.sorted = topologicalSortFr(c)
	}

	if transcriptSettings.Transcript == nil {
		challengeNames := ChallengeNamesFr(o.sorted, o.nbVars, transcriptSettings.Prefix)
		o.transcript, err = recursion.NewTranscript(api, fr.Modulus(), challengeNames)
		if err != nil {
			return o, fmt.Errorf("new transcript: %w", err)
		}
		// bind challenge from previous round if it is a continuation
		if err = v.bindChallenge(o.transcript, challengeNames[0], cfg.baseChallenges); err != nil {
			return o, fmt.Errorf("base: %w", err)
		}
	} else {
		o.transcript, o.transcriptPrefix = transcriptSettings.Transcript, transcriptSettings.Prefix
	}

	return o, err
}

// ProofSize computes how large the proof for a circuit would be. It needs nbUniqueOutputs to be set
func ProofSize[FR emulated.FieldParams](c CircuitFr[FR], logNbInstances int) int {
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

func ChallengeNamesFr[FR emulated.FieldParams](sorted []*WireFr[FR], logNbInstances int, prefix string) []string {

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

func (v *GKRVerifier[FR]) getChallengesFr(transcript *fiatshamir.Transcript, names []string) (challenges []emulated.Element[FR], err error) {
	challenges = make([]emulated.Element[FR], len(names))
	var challenge emulated.Element[FR]
	var fr FR
	for i, name := range names {
		nativeChallenge, err := transcript.ComputeChallenge(name);
		if err != nil {
			return nil, fmt.Errorf("compute challenge %s: %w", names, err)
		}
		// TODO: when implementing better way (construct from limbs instead of bits) then change 
		chBts := bits.ToBinary(v.api, nativeChallenge, bits.WithNbDigits(fr.Modulus().BitLen()))
		challenge = *v.f.FromBits(chBts...)
		challenges[i] = challenge
		
	}
	return challenges, nil
}

// Prove consistency of the claimed assignment
func Prove(api frontend.API, target *big.Int, c Circuit, assignment WireAssignment, transcriptSettings fiatshamir.Settings, options ...OptionGkr) (ProofGkr, error) {
	o, err := setup(api, c, assignment, transcriptSettings, options...)
	if err != nil {
		return nil, err
	}
	defer o.workers.Stop()

	claims := newClaimsManager(c, assignment, o)

	proof := make(ProofGkr, len(c))
	// firstChallenge called rho in the paper
	var firstChallenge []frontend.Variable
	firstChallenge, err = getChallenges(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return nil, err
	}

	wirePrefix := o.transcriptPrefix + "w"
	var baseChallenge []frontend.Variable
	for i := len(c) - 1; i >= 0; i-- {

		wire := o.sorted[i]

		if wire.IsOutput() {
			claims.add(wire, firstChallenge, assignment[wire].EvaluatePool(api, firstChallenge, claims.memPool))
		}

		claim := claims.getClaim(wire)
		if wire.noProof() { // input wires with one claim only
			proof[i] = nativeProofGKR{
				PartialSumPolys: []polynative.Polynomial{},
				FinalEvalProof:  []frontend.Variable{},
			}
		} else {
			if proof[i], err = SumcheckProve(
				api, target, claim, fiatshamir.WithTranscript(o.transcript, wirePrefix+strconv.Itoa(i)+".", baseChallenge...),
			); err != nil {
				return proof, err
			}

			finalEvalProof := proof[i].FinalEvalProof.([]frontend.Variable)
			baseChallenge = make([]frontend.Variable, len(finalEvalProof))
			for j := range finalEvalProof {
				bytes := frontend.ToBytes(finalEvalProof[j])
				baseChallenge[j] = bytes[:]
			}
		}
		// the verifier checks a single claim about input wires itself
		claims.deleteClaim(wire)
	}

	return proof, nil
}

// Verify the consistency of the claimed output with the claimed input
// Unlike in Prove, the assignment argument need not be complete, 
// Use valueOfProof[FR](proof) to convert nativeproof by prover into nonnativeproof used by in-circuit verifier
func (v *GKRVerifier[FR]) Verify(api frontend.API, c CircuitFr[FR], assignment WireAssignmentFr[FR], proof Proofs[FR], transcriptSettings fiatshamir.SettingsFr[FR], options ...OptionFr[FR]) error {
	o, err := v.setup(api, c, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}
	sumcheck_verifier, err := NewVerifier[FR](api)
	if err != nil {
		return err
	}

	claims := newClaimsManagerFr(c, assignment, *v)
	var firstChallenge []emulated.Element[FR]
	firstChallenge, err = v.getChallengesFr(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return err
	}

	wirePrefix := o.transcriptPrefix + "w"
	var baseChallenge []emulated.Element[FR]
	for i := len(c) - 1; i >= 0; i-- {
		wire := o.sorted[i]

		if wire.IsOutput() {
			var evaluation emulated.Element[FR]
			evaluationPtr, err := v.p.EvalMultilinear(polynomial.FromSlice(firstChallenge), assignment[wire])
			if err != nil {
				return err
			}
			evaluation = *evaluationPtr
			claims.add(wire, firstChallenge, evaluation)
		}

		proofW := proof[i]
		finalEvalProof := proofW.FinalEvalProof
		claim := claims.getLazyClaim(wire)

		if wire.noProof() { // input wires with one claim only
			// make sure the proof is empty
			if len(finalEvalProof) != 0 || len(proofW.PartialSumPolys) != 0 {
				return fmt.Errorf("no proof allowed for input wire with a single claim")
			}

			if wire.NbClaims() == 1 { // input wire
				// simply evaluate and see if it matches
				var evaluation emulated.Element[FR]
				evaluationPtr, err := v.p.EvalMultilinear(polynomial.FromSlice(claim.evaluationPoints[0]), assignment[wire])
				if err != nil {
					return err
				}
				evaluation = *evaluationPtr
				v.f.AssertIsEqual(&claim.claimedEvaluations[0], &evaluation)
			}
		} else if err = sumcheck_verifier.VerifyForGkr(
			claim, proof[i], fiatshamir.WithTranscriptFr(o.transcript, wirePrefix+strconv.Itoa(i)+".", baseChallenge...),
		); err == nil {
			baseChallenge = finalEvalProof
			_ = baseChallenge
		} else {
			return err
		}
		claims.deleteClaim(wire)
	}
	return nil
}

type IdentityGate struct{}

func (IdentityGate) Evaluate(input ...frontend.Variable) frontend.Variable {
	return input[0]
}

func (IdentityGate) Degree() int {
	return 1
}

// outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsList(c Circuit, indexes map[*Wire]int) [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].nbUniqueOutputs = 0
		if c[i].IsInput() {
			c[i].Gate = IdentityGate{}
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

type IdentityGateFr[FR emulated.FieldParams] struct{}

func (IdentityGateFr[FR]) Evaluate(api emuEngine[FR], input ...emulated.Element[FR]) emulated.Element[FR] {
	return input[0]
}

func (IdentityGateFr[FR]) Degree() int {
	return 1
}

// outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsListFr[FR emulated.FieldParams](c CircuitFr[FR], indexes map[*WireFr[FR]]int) [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].nbUniqueOutputs = 0
		if c[i].IsInput() {
			c[i].Gate = IdentityGateFr[FR]{}
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

type topSortDataFr[FR emulated.FieldParams] struct {
	outputs    [][]int
	status     []int // status > 0 indicates number of inputs left to be ready. status = 0 means ready. status = -1 means done
	index      map[*WireFr[FR]]int
	leastReady int
}

func (d *topSortDataFr[FR]) markDone(i int) {

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

func indexMapFr[FR emulated.FieldParams](c CircuitFr[FR]) map[*WireFr[FR]]int {
	res := make(map[*WireFr[FR]]int, len(c))
	for i := range c {
		res[&c[i]] = i
	}
	return res
}

func statusListFr[FR emulated.FieldParams](c CircuitFr[FR]) []int {
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

func topologicalSortFr[FR emulated.FieldParams](c CircuitFr[FR]) []*WireFr[FR] {
	var data topSortDataFr[FR]
	data.index = indexMapFr(c)
	data.outputs = outputsListFr(c, data.index)
	data.status = statusListFr(c)
	sorted := make([]*WireFr[FR], len(c))

	for data.leastReady = 0; data.status[data.leastReady] != 0; data.leastReady++ {
	}

	for i := range c {
		sorted[i] = &c[data.leastReady]
		data.markDone(data.leastReady)
	}

	return sorted
}

func (a WireAssignmentFr[FR]) NumInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentFr[FR]) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

func (p Proofs[FR]) Serialize() []emulated.Element[FR] {
	size := 0
	for i := range p {
		for j := range p[i].PartialSumPolys {
			size += len(p[i].PartialSumPolys[j])
		}
		size += len(p[i].FinalEvalProof)
	}

	res := make([]emulated.Element[FR], 0, size)
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

func computeLogNbInstances[FR emulated.FieldParams](wires []*WireFr[FR], serializedProofLen int) int {
	partialEvalElemsPerVar := 0
	for _, w := range wires {
		if !w.noProof() {
			partialEvalElemsPerVar += w.Gate.Degree() + 1
		}
		serializedProofLen -= w.nbUniqueOutputs
	}
	return serializedProofLen / partialEvalElemsPerVar
}

type variablesReader[FR emulated.FieldParams] []emulated.Element[FR]

func (r *variablesReader[FR]) nextN(n int) []emulated.Element[FR] {
	res := (*r)[:n]
	*r = (*r)[n:]
	return res
}

func (r *variablesReader[FR]) hasNextN(n int) bool {
	return len(*r) >= n
}

func DeserializeProof[FR emulated.FieldParams](sorted []*WireFr[FR], serializedProof []emulated.Element[FR]) (Proofs[FR], error) {
	proof := make(Proofs[FR], len(sorted))
	logNbInstances := computeLogNbInstances(sorted, len(serializedProof))

	reader := variablesReader[FR](serializedProof)
	for i, wI := range sorted {
		if !wI.noProof() {
			proof[i].PartialSumPolys = make([]polynomial.Univariate[FR], logNbInstances)
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

type MulGate[FR emulated.FieldParams] struct{}

func (g MulGate[FR]) Evaluate(api emuEngine[FR], x ...emulated.Element[FR]) emulated.Element[FR] {
	if len(x) != 2 {
		panic("mul has fan-in 2")
	}
	return *api.Mul(&x[0], &x[1])
}

// TODO: Degree must take nbInputs as an argument and return degree = nbInputs
func (g MulGate[FR]) Degree() int {
	return 2
}

type AddGate[FR emulated.FieldParams] struct{}

func (a AddGate[FR]) Evaluate(api emuEngine[FR], v ...emulated.Element[FR]) emulated.Element[FR] {
	switch len(v) {
	case 0:
		return *api.Const(big.NewInt(0))
	case 1:
		return v[0]
	}
	rest := v[2:]
	res := api.Add(&v[0], &v[1])
	for _, e := range rest {
		res = api.Add(res, &e)
	}
	return *res
}

func (a AddGate[FR]) Degree() int {
	return 1
}




