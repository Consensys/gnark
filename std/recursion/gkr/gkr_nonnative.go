package sumcheck

import (
	"fmt"
	"math/big"
	"slices"
	"strconv"
	cryptofiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/parallel"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/recursion/sumcheck"
)

// @tabaie TODO: Contains many things copy-pasted from gnark-crypto. Generify somehow?

// The goal is to prove/verify evaluations of many instances of the same circuit

// type gateinput struct {
// 	api arithEngine
// 	element ...emulated.Element
// }

// Gate must be a low-degree polynomial
type Gate interface {
	Evaluate(*sumcheck.BigIntEngine, ...*big.Int) *big.Int
	Degree() int
}

type Wire struct {
	Gate            Gate
	Inputs          []*Wire // if there are no Inputs, the wire is assumed an input wire
	nbUniqueOutputs int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

// Gate must be a low-degree polynomial
type GateEmulated[FR emulated.FieldParams] interface {
	Evaluate(*sumcheck.EmuEngine[FR], ...*emulated.Element[FR]) *emulated.Element[FR] 
	Degree() int
}

type WireEmulated[FR emulated.FieldParams] struct {
	Gate            GateEmulated[FR]
	Inputs          []*WireEmulated[FR] // if there are no Inputs, the wire is assumed an input wire
	nbUniqueOutputs int           // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
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

type CircuitEmulated[FR emulated.FieldParams] []WireEmulated[FR]

func (w WireEmulated[FR]) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w WireEmulated[FR]) IsOutput() bool {
	return w.nbUniqueOutputs == 0
}

func (w WireEmulated[FR]) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.nbUniqueOutputs
}

func (w WireEmulated[FR]) nbUniqueInputs() int {
	set := make(map[*WireEmulated[FR]]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

func (w WireEmulated[FR]) noProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[*Wire]sumcheck.NativeMultilinear

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignmentEmulated[FR emulated.FieldParams] map[*WireEmulated[FR]]polynomial.Multilinear[FR]

type Proofs[FR emulated.FieldParams] []sumcheck.Proof[FR] // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

type eqTimesGateEvalSumcheckLazyClaimsEmulated[FR emulated.FieldParams] struct {
	wire               *WireEmulated[FR]
	evaluationPoints   [][]emulated.Element[FR]
	claimedEvaluations []emulated.Element[FR]
	manager            *claimsManagerEmulated[FR] // WARNING: Circular references
	verifier           *GKRVerifier[FR]
	engine             *sumcheck.EmuEngine[FR]
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) NbClaims() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) NbVars() int {
	return len(e.evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) CombinedSum(a *emulated.Element[FR]) *emulated.Element[FR] {
	evalsAsPoly := polynomial.Univariate[FR](e.claimedEvaluations)
	return e.verifier.p.EvalUnivariate(evalsAsPoly, a)
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) Degree(int) int {
	return 1 + e.wire.Gate.Degree()
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff, expectedValue *emulated.Element[FR], proof sumcheck.EvaluationProof) error {
	inputEvaluationsNoRedundancy := proof.([]emulated.Element[FR])
	// switch proof := proof.(type) {
	// case []emulated.Element[FR]:
	// 	fmt.Println("proof type: []emulated.Element")
	// 	inputEvaluationsNoRedundancy = sumcheck.DeferredEvalProof[FR](proof)
	// default:
	// 	return fmt.Errorf("proof is not a DeferredEvalProof")
	// }
	field, err := emulated.NewField[FR](e.verifier.api)
	if err != nil {
		return fmt.Errorf("failed to create field: %w", err)
	}
	p, err := polynomial.New[FR](e.verifier.api)
	if err != nil {
		return err
	}

	// the eq terms
	numClaims := len(e.evaluationPoints)
	evaluation := p.EvalEqual(polynomial.FromSlice(e.evaluationPoints[numClaims-1]), r)
	for i := numClaims - 2; i >= 0; i-- {
		evaluation = field.Mul(evaluation, combinationCoeff)
		eq := p.EvalEqual(polynomial.FromSlice(e.evaluationPoints[i]), r)
		evaluation = field.Add(evaluation, eq)
	}

	// the g(...) term
	var gateEvaluation emulated.Element[FR]
	if e.wire.IsInput() {
		gateEvaluationPtr, err := p.EvalMultilinear(r, e.manager.assignment[e.wire])
		if err != nil {
			return err
		}
		gateEvaluation = *gateEvaluationPtr
	} else {
		inputEvaluations := make([]emulated.Element[FR], len(e.wire.Inputs))
		indexesInProof := make(map[*WireEmulated[FR]]int, len(inputEvaluationsNoRedundancy))

		proofI := 0
		for inI, in := range e.wire.Inputs {
			indexInProof, found := indexesInProof[in]
			if !found {
				indexInProof = proofI
				indexesInProof[in] = indexInProof

				// defer verification, store new claim
				e.manager.add(in, polynomial.FromSliceReferences(r), inputEvaluationsNoRedundancy[indexInProof])
				proofI++
			}
			inputEvaluations[inI] = inputEvaluationsNoRedundancy[indexInProof]
		}
		if proofI != len(inputEvaluationsNoRedundancy) {
			return fmt.Errorf("%d input wire evaluations given, %d expected", len(inputEvaluationsNoRedundancy), proofI)
		}
		gateEvaluation = *e.wire.Gate.Evaluate(e.engine, polynomial.FromSlice(inputEvaluations)...)
	}
	evaluation = field.Mul(evaluation, &gateEvaluation)

	field.AssertIsEqual(evaluation, expectedValue)
	return nil
}

type claimsManagerEmulated[FR emulated.FieldParams] struct {
	claimsMap  map[*WireEmulated[FR]]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]
	assignment WireAssignmentEmulated[FR]
}

func newClaimsManagerEmulated[FR emulated.FieldParams](c CircuitEmulated[FR], assignment WireAssignmentEmulated[FR], verifier GKRVerifier[FR]) (claims claimsManagerEmulated[FR]) {
	claims.assignment = assignment
	claims.claimsMap = make(map[*WireEmulated[FR]]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR], len(c))
	engine, err := sumcheck.NewEmulatedEngine[FR](verifier.api)
	if err != nil {
		panic(err)
	}
	for i := range c {
		wire := &c[i]

		claims.claimsMap[wire] = &eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]{
			wire:               wire,
			evaluationPoints:   make([][]emulated.Element[FR], 0, wire.NbClaims()),
			claimedEvaluations: make(polynomial.Multilinear[FR], wire.NbClaims()),
			manager:            &claims,
			verifier:           &verifier,
			engine:             engine,
		}
	}
	return
}

func (m *claimsManagerEmulated[FR]) add(wire *WireEmulated[FR], evaluationPoint []emulated.Element[FR], evaluation emulated.Element[FR]) {
	claim := m.claimsMap[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

func (m *claimsManagerEmulated[FR]) getLazyClaim(wire *WireEmulated[FR]) *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR] {
	return m.claimsMap[wire]
}

func (m *claimsManagerEmulated[FR]) deleteClaim(wire *WireEmulated[FR]) {
	delete(m.claimsMap, wire)
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
			evaluationPoints:   make([][]big.Int, 0, wire.NbClaims()),
			claimedEvaluations: make([]big.Int, wire.NbClaims()),
			manager:            &claims,
		}
	}
	return
}

func (m *claimsManager) add(wire *Wire, evaluationPoint []big.Int, evaluation big.Int) {
	claim := m.claimsMap[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

func (m *claimsManager) getClaim(engine *sumcheck.BigIntEngine, wire *Wire) *eqTimesGateEvalSumcheckClaims {
	lazy := m.claimsMap[wire]
	res := &eqTimesGateEvalSumcheckClaims{
		wire:               wire,
		evaluationPoints:   lazy.evaluationPoints,
		claimedEvaluations: lazy.claimedEvaluations,
		manager:            m,
		engine:             engine,
	}

	if wire.IsInput() {
		res.inputPreprocessors = []sumcheck.NativeMultilinear{m.assignment[wire]}
	} else {
		res.inputPreprocessors = make([]sumcheck.NativeMultilinear, len(wire.Inputs))

		for inputI, inputW := range wire.Inputs {
			res.inputPreprocessors[inputI] = m.assignment[inputW] //will be edited later, so must be deep copied
		}
	}
	return res
}

func (m *claimsManager) deleteClaim(wire *Wire) {
	delete(m.claimsMap, wire)
}

type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wire
	evaluationPoints   [][]big.Int // x in the paper
	claimedEvaluations []big.Int   // y in the paper
	manager            *claimsManager
}

type eqTimesGateEvalSumcheckClaims struct {
	wire               *Wire
	evaluationPoints   [][]big.Int // x in the paper
	claimedEvaluations []big.Int   // y in the paper
	manager            *claimsManager
	engine             *sumcheck.BigIntEngine
	inputPreprocessors []sumcheck.NativeMultilinear // P_u in the paper, so that we don't need to pass along all the circuit's evaluations

	eq sumcheck.NativeMultilinear // ∑_i τ_i eq(x_i, -)
}

func (e *eqTimesGateEvalSumcheckClaims) NbClaims() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckClaims) NbVars() int {
	return len(e.evaluationPoints[0])
}

func (c *eqTimesGateEvalSumcheckClaims) Combine(combinationCoeff *big.Int) sumcheck.NativePolynomial {
	varsNum := c.NbVars()
	eqLength := 1 << varsNum
	claimsNum := c.NbClaims()

	// initialize the eq tables
	c.eq = make(sumcheck.NativeMultilinear, eqLength)
	for i := 1; i < eqLength; i++ {
		c.eq[i] = new(big.Int)
	}
	c.eq[0] = c.engine.One()
	sumcheck.Eq(c.engine, c.eq, sumcheck.ReferenceBigIntSlice(c.evaluationPoints[0]))

	newEq := make(sumcheck.NativeMultilinear, eqLength)
	for i := 1; i < eqLength; i++ {
		newEq[i] = new(big.Int)
	}
	aI := new(big.Int).Set(combinationCoeff)

	for k := 1; k < claimsNum; k++ { // TODO: parallelizable?
		// define eq_k = aᵏ eq(x_k1, ..., x_kn, *, ..., *) where x_ki are the evaluation points
		newEq[0].Set(aI) // check if this is one or ai
		sumcheck.EqAcc(c.engine, c.eq, newEq, sumcheck.ReferenceBigIntSlice(c.evaluationPoints[k]))
		if k+1 < claimsNum {
			aI.Mul(aI, combinationCoeff)
		}
	}

	// from this point on the claim is a rather simple one: g = E(h) × R_v (P_u0(h), ...) where E and the P_u are multilinear and R_v is of low-degree
	return c.computeGJ()
}

// computeGJ: gⱼ = ∑_{0≤i<2ⁿ⁻ʲ} g(r₁, r₂, ..., rⱼ₋₁, Xⱼ, i...) = ∑_{0≤i<2ⁿ⁻ʲ} E(r₁, ..., X_j, i...) R_v( P_u0(r₁, ..., X_j, i...), ... ) where  E = ∑ eq_k
// the polynomial is represented by the evaluations g_j(1), g_j(2), ..., g_j(deg(g_j)).
// The value g_j(0) is inferred from the equation g_j(0) + g_j(1) = gⱼ₋₁(rⱼ₋₁). By convention, g₀ is a constant polynomial equal to the claimed sum.
func (c *eqTimesGateEvalSumcheckClaims) computeGJ() sumcheck.NativePolynomial {

	degGJ := 1 + c.wire.Gate.Degree() // guaranteed to be no smaller than the actual deg(g_j)
	nbGateIn := len(c.inputPreprocessors)

	// Let f ∈ { E(r₁, ..., X_j, d...) } ∪ {P_ul(r₁, ..., X_j, d...) }. It is linear in X_j, so f(m) = m×(f(1) - f(0)) + f(0), and f(0), f(1) are easily computed from the bookkeeping tables
	s := make([]sumcheck.NativeMultilinear, nbGateIn+1)
	s[0] = c.eq
	copy(s[1:], c.inputPreprocessors)

	// Perf-TODO: Collate once at claim "combination" time and not again. then, even folding can be done in one operation every time "next" is called
	nbInner := len(s) // wrt output, which has high nbOuter and low nbInner
	nbOuter := len(s[0]) / 2

	gJ := make(sumcheck.NativePolynomial, degGJ)
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
			step = c.engine.Sub(operands[j], step)
			for d := 1; d < degGJ; d++ {
				operands[d*nbInner+j] = c.engine.Add(operands[(d-1)*nbInner+j], step)
			}
		}
		_s := 0
		_e := nbInner
		for d := 0; d < degGJ; d++ {
			summand := c.wire.Gate.Evaluate(c.engine, operands[_s+1:_e]...)
			summand = c.engine.Mul(summand, operands[_s])
			res[d] = c.engine.Add(res[d], summand)
			_s, _e = _e, _e+nbInner
		}
	}
	for i := 0; i < degGJ; i++ {
		gJ[i] = c.engine.Add(gJ[i], res[i])
	}
	return gJ
}

// Next first folds the "preprocessing" and "eq" polynomials then compute the new g_j
func (c *eqTimesGateEvalSumcheckClaims) Next(element *big.Int) sumcheck.NativePolynomial {
	for i := 0; i < len(c.inputPreprocessors); i++ {
		sumcheck.Fold(c.engine, c.inputPreprocessors[i], element)
	}
	sumcheck.Fold(c.engine, c.eq, element)

	return c.computeGJ()
}

func (c *eqTimesGateEvalSumcheckClaims) ProverFinalEval(r []*big.Int) sumcheck.NativeEvaluationProof {

	//defer the proof, return list of claims
	evaluations := make([]big.Int, 0, len(c.wire.Inputs))
	noMoreClaimsAllowed := make(map[*Wire]struct{}, len(c.inputPreprocessors))
	noMoreClaimsAllowed[c.wire] = struct{}{}

	for inI, in := range c.wire.Inputs {
		puI := c.inputPreprocessors[inI]
		if _, found := noMoreClaimsAllowed[in]; !found {
			noMoreClaimsAllowed[in] = struct{}{}
			sumcheck.Fold(c.engine, puI, r[len(r)-1])
			c.manager.add(in, sumcheck.DereferenceBigIntSlice(r), *puI[0])
			evaluations = append(evaluations, *puI[0])
		}
	}

	return evaluations
}

func (e *eqTimesGateEvalSumcheckClaims) Degree(int) int {
	return 1 + e.wire.Gate.Degree()
}

func setup(current *big.Int, target *big.Int, c Circuit, assignment WireAssignment, options ...OptionGkr) (settings, error) {
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

	if o.sorted == nil {
		o.sorted = topologicalSort(c)
	}

	if o.transcript == nil {

		challengeNames := ChallengeNames(o.sorted, o.nbVars, o.transcriptPrefix)
		fshash, err := recursion.NewShort(current, target)
		if err != nil {
			return o, fmt.Errorf("new short hash: %w", err)
		}
		o.transcript = cryptofiatshamir.NewTranscript(fshash, challengeNames...)

		// bind challenge from previous round if it is a continuation
		if err = sumcheck.BindChallengeProver(o.transcript, challengeNames[0], o.baseChallenges); err != nil {
			return o, fmt.Errorf("base: %w", err)
		}

	}

	return o, err
}

type settings struct {
	sorted           []*Wire
	transcript       *cryptofiatshamir.Transcript
	baseChallenges   []*big.Int
	transcriptPrefix string
	nbVars           int
}

type OptionSet func(*settings)

func WithSortedCircuitSet(sorted []*Wire) OptionSet {
	return func(options *settings) {
		options.sorted = sorted
	}
}

type NativeProofs []sumcheck.NativeProof

type OptionGkr func(*settings)

type SettingsEmulated[FR emulated.FieldParams] struct {
	sorted           []*WireEmulated[FR]
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
}

type OptionEmulated[FR emulated.FieldParams] func(*SettingsEmulated[FR])

func WithSortedCircuitEmulated[FR emulated.FieldParams](sorted []*WireEmulated[FR]) OptionEmulated[FR] {
	return func(options *SettingsEmulated[FR]) {
		options.sorted = sorted
	}
}

// type config struct {
// 	prefix string
// }

// func newConfig(opts ...sumcheck.Option) (*config, error) {
// 	cfg := new(config)
// 	for i := range opts {
// 		if err := opts[i](cfg); err != nil {
// 			return nil, fmt.Errorf("apply option %d: %w", i, err)
// 		}
// 	}
// 	return cfg, nil
// }

// Verifier allows to check sumcheck proofs. See [NewVerifier] for initializing the instance.
type GKRVerifier[FR emulated.FieldParams] struct {
	api    frontend.API
	f      *emulated.Field[FR]
	p      *polynomial.Polynomial[FR]
	*sumcheck.Config
}

// NewVerifier initializes a new sumcheck verifier for the parametric emulated
// field FR. It returns an error if the given options are invalid or when
// initializing emulated arithmetic fails.
func NewGKRVerifier[FR emulated.FieldParams](api frontend.API, opts ...sumcheck.Option) (*GKRVerifier[FR], error) {
	cfg, err := sumcheck.NewConfig(opts...)
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
		Config: cfg,
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

func (v *GKRVerifier[FR]) setup(api frontend.API, c CircuitEmulated[FR], assignment WireAssignmentEmulated[FR], transcriptSettings fiatshamir.SettingsEmulated[FR], options ...OptionEmulated[FR]) (SettingsEmulated[FR], error) {
	var fr FR
	var o SettingsEmulated[FR]
	var err error
	for _, option := range options {
		option(&o)
	}

	cfg, err := sumcheck.NewVerificationConfig[FR]()
	if err != nil {
		return o, fmt.Errorf("verification opts: %w", err)
	}

	o.nbVars = assignment.NumVars()
	nbInstances := assignment.NumInstances()
	if 1<<o.nbVars != nbInstances {
		return o, fmt.Errorf("number of instances must be power of 2")
	}

	if o.sorted == nil {
		o.sorted = topologicalSortEmulated(c)
	}

	if transcriptSettings.Transcript == nil {
		challengeNames := ChallengeNamesEmulated(o.sorted, o.nbVars, transcriptSettings.Prefix)
		o.transcript, err = recursion.NewTranscript(api, fr.Modulus(), challengeNames)
		if err != nil {
			return o, fmt.Errorf("new transcript: %w", err)
		}
		// bind challenge from previous round if it is a continuation
		if err = v.bindChallenge(o.transcript, challengeNames[0], cfg.BaseChallenges); err != nil {
			return o, fmt.Errorf("base: %w", err)
		}
	} else {
		o.transcript, o.transcriptPrefix = transcriptSettings.Transcript, transcriptSettings.Prefix
	}

	return o, err
}

// ProofSize computes how large the proof for a circuit would be. It needs nbUniqueOutputs to be set
func ProofSize[FR emulated.FieldParams](c CircuitEmulated[FR], logNbInstances int) int {
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

func ChallengeNamesEmulated[FR emulated.FieldParams](sorted []*WireEmulated[FR], logNbInstances int, prefix string) []string {

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

func (v *GKRVerifier[FR]) getChallengesFr(transcript *fiatshamir.Transcript, names []string) (challenges []emulated.Element[FR], err error) {
	challenges = make([]emulated.Element[FR], len(names))
	var challenge emulated.Element[FR]
	var fr FR
	for i, name := range names {
		nativeChallenge, err := transcript.ComputeChallenge(name)
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
func Prove(current *big.Int, target *big.Int, c Circuit, assignment WireAssignment, transcriptSettings fiatshamir.SettingsBigInt, options ...OptionGkr) (NativeProofs, error) {
	be := sumcheck.NewBigIntEngine(target)
	o, err := setup(current, target, c, assignment, options...)
	if err != nil {
		return nil, err
	}

	claims := newClaimsManager(c, assignment)

	proof := make(NativeProofs, len(c))
	challengeNames := getFirstChallengeNames(o.nbVars, o.transcriptPrefix)
	// firstChallenge called rho in the paper
	firstChallenge := make([]*big.Int, len(challengeNames))
	for i := 0; i < len(challengeNames); i++ {
		firstChallenge[i], _, err = sumcheck.DeriveChallengeProver(o.transcript, challengeNames[i:], nil)
		if err != nil {
			return nil, err
		}
	}

	var baseChallenge []*big.Int
	for i := len(c) - 1; i >= 0; i-- {
		wire := o.sorted[i]

		if wire.IsOutput() {
			evaluation := sumcheck.Eval(be, assignment[wire], firstChallenge)
			claims.add(wire, sumcheck.DereferenceBigIntSlice(firstChallenge), *evaluation)
		}

		claim := claims.getClaim(be, wire)
		var finalEvalProofLen int
		finalEvalProof := proof[i].FinalEvalProof

		if wire.noProof() { // input wires with one claim only
			proof[i] = sumcheck.NativeProof{
				RoundPolyEvaluations: []sumcheck.NativePolynomial{},
				FinalEvalProof:  finalEvalProof,
			}
		} else {
			proof[i], err = sumcheck.Prove(
				current, target, claim,
			)
			if err != nil {
				return proof, err
			}

			finalEvalProof := proof[i].FinalEvalProof
			switch finalEvalProof := finalEvalProof.(type) {
			case nil:
				finalEvalProof = sumcheck.NativeDeferredEvalProof([]big.Int{})
			case []big.Int:
				finalEvalProofLen = len(finalEvalProof)
				finalEvalProof = sumcheck.NativeDeferredEvalProof(finalEvalProof)
			default:
				return nil, fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
			}

			proof[i].FinalEvalProof = finalEvalProof
			baseChallenge = make([]*big.Int, finalEvalProofLen)
			for i := 0; i < finalEvalProofLen; i++ {
				baseChallenge[i] = &finalEvalProof.([]big.Int)[i]
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
func (v *GKRVerifier[FR]) Verify(api frontend.API, c CircuitEmulated[FR], assignment WireAssignmentEmulated[FR], proof Proofs[FR], transcriptSettings fiatshamir.SettingsEmulated[FR], options ...OptionEmulated[FR]) error {
	o, err := v.setup(api, c, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}
	sumcheck_verifier, err := sumcheck.NewVerifier[FR](api)
	if err != nil {
		return err
	}

	claims := newClaimsManagerEmulated[FR](c, assignment, *v)
	var firstChallenge []emulated.Element[FR]
	firstChallenge, err = v.getChallengesFr(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return err
	}

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
			// make sure finalevalproof is of type deferred for gkr
			var proofLen int
			switch proof := finalEvalProof.(type) {
			case []emulated.Element[FR]:
				proofLen = len(sumcheck.DeferredEvalProof[FR](proof))
			default:
				return fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
			}
			
			if (finalEvalProof != nil && proofLen != 0) || len(proofW.RoundPolyEvaluations) != 0 {
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
		} else if err = sumcheck_verifier.Verify(
			claim, proof[i],
		); err == nil {
			switch proof := finalEvalProof.(type) {
			case []emulated.Element[FR]:
				baseChallenge = sumcheck.DeferredEvalProof[FR](proof)
			default:
				return fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
			}
			_ = baseChallenge
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
			c[i].Gate = IdentityGate[*sumcheck.BigIntEngine, *big.Int]{}
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

type IdentityGate[AE sumcheck.ArithEngine[E], E element] struct{}

func (IdentityGate[AE, E]) Evaluate(api AE, input ...E) E {
	return input[0]
}

func (IdentityGate[AE, E]) Degree() int {
	return 1
}

// outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsListEmulated[FR emulated.FieldParams](c CircuitEmulated[FR], indexes map[*WireEmulated[FR]]int) [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].nbUniqueOutputs = 0
		if c[i].IsInput() {
			c[i].Gate = IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{}
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

type topSortDataEmulated[FR emulated.FieldParams] struct {
	outputs    [][]int
	status     []int // status > 0 indicates number of inputs left to be ready. status = 0 means ready. status = -1 means done
	index      map[*WireEmulated[FR]]int
	leastReady int
}

func (d *topSortDataEmulated[FR]) markDone(i int) {

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

func indexMapEmulated[FR emulated.FieldParams](c CircuitEmulated[FR]) map[*WireEmulated[FR]]int {
	res := make(map[*WireEmulated[FR]]int, len(c))
	for i := range c {
		res[&c[i]] = i
	}
	return res
}

func statusListEmulated[FR emulated.FieldParams](c CircuitEmulated[FR]) []int {
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

// Complete the circuit evaluation from input values
func (a WireAssignment) Complete(c Circuit, target *big.Int) WireAssignment {

	engine := sumcheck.NewBigIntEngine(target)
	sortedWires := topologicalSort(c)
	nbInstances := a.NumInstances()
	maxNbIns := 0

	for _, w := range sortedWires {
		maxNbIns = utils.Max(maxNbIns, len(w.Inputs))
		if a[w] == nil {
			a[w] = make([]*big.Int, nbInstances)
		}
	}

	parallel.Execute(nbInstances, func(start, end int) {
		ins := make([]*big.Int, maxNbIns)
		for i := start; i < end; i++ {
			for _, w := range sortedWires {
				if !w.IsInput() {
					for inI, in := range w.Inputs {
						ins[inI] = a[in][i]
					}
					a[w][i] = w.Gate.Evaluate(engine, ins[:len(w.Inputs)]...)
				}
			}
		}
	})

	return a
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

func topologicalSortEmulated[FR emulated.FieldParams](c CircuitEmulated[FR]) []*WireEmulated[FR] {
	var data topSortDataEmulated[FR]
	data.index = indexMapEmulated(c)
	data.outputs = outputsListEmulated(c, data.index)
	data.status = statusListEmulated(c)
	sorted := make([]*WireEmulated[FR], len(c))

	for data.leastReady = 0; data.status[data.leastReady] != 0; data.leastReady++ {
	}

	for i := range c {
		sorted[i] = &c[data.leastReady]
		data.markDone(data.leastReady)
	}

	return sorted
}

func (a WireAssignmentEmulated[FR]) NumInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentEmulated[FR]) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

// func (p Proofs[FR]) Serialize() []emulated.Element[FR] {
// 	size := 0
// 	for i := range p {
// 		for j := range p[i].RoundPolyEvaluations {
// 			size += len(p[i].RoundPolyEvaluations[j])
// 		}
// 		size += len(p[i].FinalEvalProof.(sumcheck.DeferredEvalProof[FR]))
// 	}

// 	res := make([]emulated.Element[FR], 0, size)
// 	for i := range p {
// 		for j := range p[i].RoundPolyEvaluations {
// 			res = append(res, p[i].RoundPolyEvaluations[j]...)
// 		}
// 		res = append(res, p[i].FinalEvalProof.(sumcheck.DeferredEvalProof[FR])...)
// 	}
// 	if len(res) != size {
// 		panic("bug") // TODO: Remove
// 	}
// 	return res
// }

func (p Proofs[FR]) Serialize() []emulated.Element[FR] {
	size := 0
	for i := range p {
		for j := range p[i].RoundPolyEvaluations {
			size += len(p[i].RoundPolyEvaluations[j])
		}
		switch v := p[i].FinalEvalProof.(type) {
		case sumcheck.DeferredEvalProof[FR]:
			size += len(v)
		}
	}

	res := make([]emulated.Element[FR], 0, size)
	for i := range p {
		for j := range p[i].RoundPolyEvaluations {
			res = append(res, p[i].RoundPolyEvaluations[j]...)
		}
		switch v := p[i].FinalEvalProof.(type) {
		case sumcheck.DeferredEvalProof[FR]:
			res = append(res, v...)
		}
	}
	if len(res) != size {
		panic("bug") // TODO: Remove
	}
	return res
}

func computeLogNbInstances[FR emulated.FieldParams](wires []*WireEmulated[FR], serializedProofLen int) int {
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

func DeserializeProof[FR emulated.FieldParams](sorted []*WireEmulated[FR], serializedProof []emulated.Element[FR]) (Proofs[FR], error) {
	proof := make(Proofs[FR], len(sorted))
	logNbInstances := computeLogNbInstances(sorted, len(serializedProof))

	reader := variablesReader[FR](serializedProof)
	for i, wI := range sorted {
		if !wI.noProof() {
			proof[i].RoundPolyEvaluations = make([]polynomial.Univariate[FR], logNbInstances)
			for j := range proof[i].RoundPolyEvaluations {
				proof[i].RoundPolyEvaluations[j] = reader.nextN(wI.Gate.Degree() + 1)
			}
		}
		proof[i].FinalEvalProof = reader.nextN(wI.nbUniqueInputs())
	}
	if reader.hasNextN(1) {
		return nil, fmt.Errorf("proof too long: expected %d encountered %d", len(serializedProof)-len(reader), len(serializedProof))
	}
	return proof, nil
}

type element any 

type MulGate[AE sumcheck.ArithEngine[E], E element] struct{}

func (g MulGate[AE, E]) Evaluate(api AE, x ...E) E {
	if len(x) != 2 {
		panic("mul has fan-in 2")
	}
	return api.Mul(x[0], x[1])
}

// TODO: Degree must take nbInputs as an argument and return degree = nbInputs
func (g MulGate[AE, E]) Degree() int {
	return 2
}

type AddGate[AE sumcheck.ArithEngine[E], E element] struct{}

func (a AddGate[AE, E]) Evaluate(api AE, v ...E) E {
	switch len(v) {
	case 0:
		return api.Const(big.NewInt(0))
	case 1:
		return v[0]
	}
	rest := v[2:]
	res := api.Add(v[0], v[1])
	for _, e := range rest {
		res = api.Add(res, e)
	}
	return res
}

func (a AddGate[AE, E]) Degree() int {
	return 1
}
