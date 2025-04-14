// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package gkr

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr/polynomial"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/utils"
	"math/big"
	"strconv"
	"sync"
)

// The goal is to prove/verify evaluations of many instances of the same circuit

// GateFunction a polynomial defining a gate. It may modify its input. The changes will be ignored.
type GateFunction func(...fr.Element) fr.Element

// A Gate is a low-degree multivariate polynomial
type Gate struct {
	Evaluate    GateFunction // Evaluate the polynomial function defining the gate
	nbIn        int          // number of inputs
	degree      int          // total degree of the polynomial
	solvableVar int          // if there is a solvable variable, its index, -1 otherwise
}

// Degree returns the total degree of the gate's polynomial e.g. Degree(xy²) = 3
func (g *Gate) Degree() int {
	return g.degree
}

// SolvableVar returns I such that x_I can always be determined from {xᵢ} - x_I and f(x...). If there is no such variable, it returns -1.
func (g *Gate) SolvableVar() int {
	return g.solvableVar
}

// NbIn returns the number of inputs to the gate (its fan-in)
func (g *Gate) NbIn() int {
	return g.nbIn
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

func (w Wire) noProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

func (c Circuit) maxGateDegree() int {
	res := 1
	for i := range c {
		if !c[i].IsInput() {
			res = max(res, c[i].Gate.Degree())
		}
	}
	return res
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[*Wire]polynomial.MultiLin

type Proof []sumcheckProof // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

// eqTimesGateEvalSumcheckLazyClaims is a lazy claim for sumcheck (verifier side).
// eqTimesGateEval is a polynomial consisting of ∑ᵢ cⁱ eq(-, xᵢ) w(-).
// Its purpose is to batch the checking of multiple evaluations of the same wire.
type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wire          // the wire for which we are making the claim, with value w
	evaluationPoints   [][]fr.Element // xᵢ: the points at which the prover has made claims about the evaluation of w
	claimedEvaluations []fr.Element   // yᵢ = w(xᵢ), allegedly
	manager            *claimsManager // WARNING: Circular references
}

func (e *eqTimesGateEvalSumcheckLazyClaims) claimsNum() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) varsNum() int {
	return len(e.evaluationPoints[0])
}

// combinedSum returns ∑ᵢ aⁱ yᵢ
func (e *eqTimesGateEvalSumcheckLazyClaims) combinedSum(a fr.Element) fr.Element {
	evalsAsPoly := polynomial.Polynomial(e.claimedEvaluations)
	return evalsAsPoly.Eval(&a)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) degree(int) int {
	return 1 + e.wire.Gate.Degree()
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
func (e *eqTimesGateEvalSumcheckLazyClaims) verifyFinalEval(r []fr.Element, combinationCoeff, purportedValue fr.Element, inputEvaluationsNoRedundancy []fr.Element) error {
	// the eq terms ( E )
	numClaims := len(e.evaluationPoints)
	evaluation := polynomial.EvalEq(e.evaluationPoints[numClaims-1], r)
	for i := numClaims - 2; i >= 0; i-- {
		evaluation.Mul(&evaluation, &combinationCoeff)
		eq := polynomial.EvalEq(e.evaluationPoints[i], r)
		evaluation.Add(&evaluation, &eq)
	}

	// the w(...) term
	var gateEvaluation fr.Element
	if e.wire.IsInput() { // just compute w(r)
		gateEvaluation = e.manager.assignment[e.wire].Evaluate(r, e.manager.memPool)
	} else { // proof contains the evaluations of the inputs, but avoids repetition in case multiple inputs come from the same wire
		inputEvaluations := make([]fr.Element, len(e.wire.Inputs))
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
		gateEvaluation = e.wire.Gate.Evaluate(inputEvaluations...)
	}

	evaluation.Mul(&evaluation, &gateEvaluation)

	if evaluation.Equal(&purportedValue) {
		return nil
	}
	return errors.New("incompatible evaluations")
}

// eqTimesGateEvalSumcheckClaims is a claim for sumcheck (prover side).
// eqTimesGateEval is a polynomial consisting of ∑ᵢ cⁱ eq(-, xᵢ) w(-).
// Its purpose is to batch the proving of multiple evaluations of the same wire.
type eqTimesGateEvalSumcheckClaims struct {
	wire               *Wire          // the wire for which we are making the claim, with value w
	evaluationPoints   [][]fr.Element // xᵢ: the points at which the prover has made claims about the evaluation of w
	claimedEvaluations []fr.Element   // yᵢ = w(xᵢ)
	manager            *claimsManager

	input []polynomial.MultiLin // input[i](h₁, ..., hₘ₋ⱼ) = wᵢ(r₁, r₂, ..., rⱼ₋₁, h₁, ..., hₘ₋ⱼ)

	eq polynomial.MultiLin // E := ∑ᵢ cⁱ eq(xᵢ, -)
}

// combine the multiple claims into one claim using a random combination (combinationCoeff or c).
// From the original multiple claims of w(xᵢ) = yᵢ, we get a single claim
// ∑ᵢ,ₕ cⁱ eq(xᵢ, h) w(h) = ∑ᵢ cⁱ yᵢ, where h iterates over the hypercube (circuit instances) and
// i iterates over the claims.
// Equivalently, we could say ∑ᵢ cⁱ yᵢ = ∑ₕ,ᵢ cⁱ eq(xᵢ, h) w(h) = ∑ₕ w(h) ∑ᵢ cⁱ eq(xᵢ, h).
// Thus if we initially compute E := ∑ᵢ cⁱ eq(xᵢ, -), our claim will find the simpler form
// ∑ᵢ cⁱ yᵢ = ∑ₕ w(h) E(h), where the sum-checked polynomial is of degree deg(g) + 1,
// and deg(g) is the total degree of the polynomial defining the gate g of which w is the output.
// The output of combine is the first sumcheck claim, i.e. ∑₍ₕ₁,ₕ₂,...₎ w(X, h₁, h₂, ...) E(X, h₁, h₂, ...)..
func (c *eqTimesGateEvalSumcheckClaims) combine(combinationCoeff fr.Element) polynomial.Polynomial {
	varsNum := c.varsNum()
	eqLength := 1 << varsNum
	claimsNum := c.claimsNum()
	// initialize the eq tables ( E )
	c.eq = c.manager.memPool.Make(eqLength)

	c.eq[0].SetOne()
	c.eq.Eq(c.evaluationPoints[0])

	// E := eq(x₀, -)
	newEq := polynomial.MultiLin(c.manager.memPool.Make(eqLength))
	aI := combinationCoeff

	// E += cⁱ eq(xᵢ, -)
	for k := 1; k < claimsNum; k++ {
		newEq[0].Set(&aI)

		c.eqAcc(c.eq, newEq, c.evaluationPoints[k])

		if k+1 < claimsNum {
			aI.Mul(&aI, &combinationCoeff)
		}
	}

	c.manager.memPool.Dump(newEq)

	return c.computeGJ()
}

// eqAcc sets m to an eq table at q and then adds it to e.
// m <- eq(q, -).
// e <- e + m
func (c *eqTimesGateEvalSumcheckClaims) eqAcc(e, m polynomial.MultiLin, q []fr.Element) {
	n := len(q)

	//At the end of each iteration, m(h₁, ..., hₙ) = eq(q₁, ..., qᵢ₊₁, h₁, ..., hᵢ₊₁)
	for i := range q { // In the comments we use a 1-based index so q[i] = qᵢ₊₁
		// go through all assignments of (b₁, ..., bᵢ) ∈ {0,1}ⁱ
		const threshold = 1 << 6
		k := 1 << i
		if k < threshold {
			for j := 0; j < k; j++ {
				j0 := j << (n - i)    // bᵢ₊₁ = 0
				j1 := j0 + 1<<(n-1-i) // bᵢ₊₁ = 1

				m[j1].Mul(&q[i], &m[j0])  // eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 1) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) eq(qᵢ₊₁, 1) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) qᵢ₊₁
				m[j0].Sub(&m[j0], &m[j1]) // eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 0) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) eq(qᵢ₊₁, 0) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) (1-qᵢ₊₁)
			}
		} else {
			c.manager.workers.Submit(k, func(start, end int) {
				for j := start; j < end; j++ {
					j0 := j << (n - i)    // bᵢ₊₁ = 0
					j1 := j0 + 1<<(n-1-i) // bᵢ₊₁ = 1

					m[j1].Mul(&q[i], &m[j0])  // eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 1) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) eq(qᵢ₊₁, 1) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) qᵢ₊₁
					m[j0].Sub(&m[j0], &m[j1]) // eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 0) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) eq(qᵢ₊₁, 0) = eq(q₁, ..., qᵢ, b₁, ..., bᵢ) (1-qᵢ₊₁)
				}
			}, 1024).Wait()
		}

	}
	c.manager.workers.Submit(len(e), func(start, end int) {
		for i := start; i < end; i++ {
			e[i].Add(&e[i], &m[i])
		}
	}, 512).Wait()
}

// computeGJ: gⱼ = ∑_{0≤h<2ⁿ⁻ʲ} g(r₁, r₂, ..., rⱼ₋₁, Xⱼ, h...) = ∑_{0≤i<2ⁿ⁻ʲ} E(r₁, ..., Xⱼ, h...) g( w₀(r₁, ..., Xⱼ, h...), ... ).
// the polynomial is represented by the evaluations gⱼ(1), gⱼ(2), ..., gⱼ(deg(gⱼ)).
// The value gⱼ(0) is inferred from the equation gⱼ(0) + gⱼ(1) = gⱼ₋₁(rⱼ₋₁). By convention, g₀ is a constant polynomial equal to the claimed sum.
func (c *eqTimesGateEvalSumcheckClaims) computeGJ() polynomial.Polynomial {

	degGJ := 1 + c.wire.Gate.Degree() // guaranteed to be no smaller than the actual deg(gⱼ)
	nbGateIn := len(c.input)

	// Both E and wᵢ (the input wires and the eq table) are multilinear, thus
	// they are linear in Xⱼ.
	// So for f ∈ { E(r₁, ..., Xⱼ, h...) } ∪ {wᵢ(r₁, ..., Xⱼ, h...) }, so f(m) = m×(f(1) - f(0)) + f(0), and f(0), f(1) are easily computed from the bookkeeping tables.
	// ml are such multilinear polynomials the evaluations of which over different values of Xⱼ are computed in this stepwise manner.
	ml := make([]polynomial.MultiLin, nbGateIn+1)
	ml[0] = c.eq
	copy(ml[1:], c.input)

	sumSize := len(c.eq) / 2 // the range of h, over which we sum

	// Perf-TODO: Collate once at claim "combination" time and not again. then, even folding can be done in one operation every time "next" is called

	gJ := make([]fr.Element, degGJ)
	var mu sync.Mutex
	computeAll := func(start, end int) { // compute method to allow parallelization across instances
		var step fr.Element

		res := make([]fr.Element, degGJ)
		// evaluations of ml, laid out as:
		// ml[0](1, h...), ml[1](1, h...), ..., ml[len(ml)-1](1, h...),
		// ml[0](2, h...), ml[1](2, h...), ..., ml[len(ml)-1](2, h...),
		// ...
		// ml[0](degGJ, h...), ml[2](degGJ, h...), ..., ml[len(ml)-1](degGJ, h...)
		// Thus the contribution of the
		mlEvals := make([]fr.Element, degGJ*len(ml))

		for h := start; h < end; h++ { // h counts across instances

			evalAt1Index := sumSize + h
			for k := range ml {
				// d = 0
				mlEvals[k].Set(&ml[k][evalAt1Index]) // evaluation at Xⱼ = 1. Can be taken directly from the table.
				step.Sub(&mlEvals[k], &ml[k][h])     // step = ml[k](1) - ml[k](0)
				for d := 1; d < degGJ; d++ {
					mlEvals[d*len(ml)+k].Add(&mlEvals[(d-1)*len(ml)+k], &step)
				}
			}

			eIndex := 0
			nextEIndex := len(ml)
			for d := range degGJ {
				summand := c.wire.Gate.Evaluate(mlEvals[eIndex+1 : nextEIndex]...)
				summand.Mul(&summand, &mlEvals[eIndex])
				res[d].Add(&res[d], &summand) // collect contributions into the sum from start to end
				eIndex, nextEIndex = nextEIndex, nextEIndex+len(ml)
			}
		}
		mu.Lock()
		for i := range gJ {
			gJ[i].Add(&gJ[i], &res[i]) // collect into the complete sum
		}
		mu.Unlock()
	}

	const minBlockSize = 64

	if sumSize < minBlockSize {
		// no parallelization
		computeAll(0, sumSize)
	} else {
		c.manager.workers.Submit(sumSize, computeAll, minBlockSize).Wait()
	}

	return gJ
}

// next first folds the input and E polynomials at the given verifier challenge then computes the new gⱼ.
// Thus, j <- j+1 and rⱼ = challenge.
func (c *eqTimesGateEvalSumcheckClaims) next(challenge fr.Element) polynomial.Polynomial {
	const minBlockSize = 512
	n := len(c.eq) / 2
	if n < minBlockSize {
		// no parallelization
		for i := 0; i < len(c.input); i++ {
			c.input[i].Fold(challenge)
		}
		c.eq.Fold(challenge)
	} else {
		wgs := make([]*sync.WaitGroup, len(c.input))
		for i := 0; i < len(c.input); i++ {
			wgs[i] = c.manager.workers.Submit(n, c.input[i].FoldParallel(challenge), minBlockSize)
		}
		c.manager.workers.Submit(n, c.eq.FoldParallel(challenge), minBlockSize).Wait()
		for _, wg := range wgs {
			wg.Wait()
		}
	}

	return c.computeGJ()
}

func (c *eqTimesGateEvalSumcheckClaims) varsNum() int {
	return len(c.evaluationPoints[0])
}

func (c *eqTimesGateEvalSumcheckClaims) claimsNum() int {
	return len(c.claimedEvaluations)
}

// proveFinalEval provides the values wᵢ(r₁, ..., rₙ)
func (c *eqTimesGateEvalSumcheckClaims) proveFinalEval(r []fr.Element) []fr.Element {

	//defer the proof, return list of claims
	evaluations := make([]fr.Element, 0, len(c.wire.Inputs))
	noMoreClaimsAllowed := make(map[*Wire]struct{}, len(c.input)) // we don't double report wires, in case a gate takes the same wire as multiple input variables.
	noMoreClaimsAllowed[c.wire] = struct{}{}

	for inI, in := range c.wire.Inputs {
		wI := c.input[inI]
		if _, found := noMoreClaimsAllowed[in]; !found {
			noMoreClaimsAllowed[in] = struct{}{}
			wI.Fold(r[len(r)-1]) // We already have wᵢ(r₁, ..., rₙ₋₁, hₙ) in a table. Only one more fold required.
			c.manager.add(in, r, wI[0])
			evaluations = append(evaluations, wI[0])
		}
		c.manager.memPool.Dump(wI)
	}

	c.manager.memPool.Dump(c.claimedEvaluations, c.eq)

	return evaluations
}

type claimsManager struct {
	claimsMap  map[*Wire]*eqTimesGateEvalSumcheckLazyClaims
	assignment WireAssignment
	memPool    *polynomial.Pool
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
			evaluationPoints:   make([][]fr.Element, 0, wire.NbClaims()),
			claimedEvaluations: claims.memPool.Make(wire.NbClaims()),
			manager:            &claims,
		}
	}
	return
}

func (m *claimsManager) add(wire *Wire, evaluationPoint []fr.Element, evaluation fr.Element) {
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
		res.input = []polynomial.MultiLin{m.memPool.Clone(m.assignment[wire])}
	} else {
		res.input = make([]polynomial.MultiLin, len(wire.Inputs))

		for inputI, inputW := range wire.Inputs {
			res.input[inputI] = m.memPool.Clone(m.assignment[inputW]) //will be edited later, so must be deep copied
		}
	}
	return res
}

func (m *claimsManager) deleteClaim(wire *Wire) {
	delete(m.claimsMap, wire)
}

type settings struct {
	pool             *polynomial.Pool
	sorted           []*Wire
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
	workers          *utils.WorkerPool
}

type Option func(*settings)

func WithPool(pool *polynomial.Pool) Option {
	return func(options *settings) {
		options.pool = pool
	}
}

func WithSortedCircuit(sorted []*Wire) Option {
	return func(options *settings) {
		options.sorted = sorted
	}
}

func WithWorkers(workers *utils.WorkerPool) Option {
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

func setup(c Circuit, assignment WireAssignment, transcriptSettings fiatshamir.Settings, options ...Option) (settings, error) {
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

	if o.pool == nil {
		pool := polynomial.NewPool(c.MemoryRequirements(nbInstances)...)
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
		o.transcript = fiatshamir.NewTranscript(transcriptSettings.Hash, challengeNames...)
		for i := range transcriptSettings.BaseChallenges {
			if err = o.transcript.Bind(challengeNames[0], transcriptSettings.BaseChallenges[i]); err != nil {
				return o, err
			}
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

func getChallenges(transcript *fiatshamir.Transcript, names []string) ([]fr.Element, error) {
	res := make([]fr.Element, len(names))
	for i, name := range names {
		if bytes, err := transcript.ComputeChallenge(name); err == nil {
			res[i].SetBytes(bytes)
		} else {
			return nil, err
		}
	}
	return res, nil
}

// Prove consistency of the claimed assignment
func Prove(c Circuit, assignment WireAssignment, transcriptSettings fiatshamir.Settings, options ...Option) (Proof, error) {
	o, err := setup(c, assignment, transcriptSettings, options...)
	if err != nil {
		return nil, err
	}
	defer o.workers.Stop()

	claims := newClaimsManager(c, assignment, o)

	proof := make(Proof, len(c))
	// firstChallenge called rho in the paper
	var firstChallenge []fr.Element
	firstChallenge, err = getChallenges(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return nil, err
	}

	wirePrefix := o.transcriptPrefix + "w"
	var baseChallenge [][]byte
	for i := len(c) - 1; i >= 0; i-- {

		wire := o.sorted[i]

		if wire.IsOutput() {
			claims.add(wire, firstChallenge, assignment[wire].Evaluate(firstChallenge, claims.memPool))
		}

		claim := claims.getClaim(wire)
		if wire.noProof() { // input wires with one claim only
			proof[i] = sumcheckProof{
				partialSumPolys: []polynomial.Polynomial{},
				finalEvalProof:  []fr.Element{},
			}
		} else {
			if proof[i], err = sumcheckProve(
				claim, fiatshamir.WithTranscript(o.transcript, wirePrefix+strconv.Itoa(i)+".", baseChallenge...),
			); err != nil {
				return proof, err
			}

			baseChallenge = make([][]byte, len(proof[i].finalEvalProof))
			for j := range proof[i].finalEvalProof {
				baseChallenge[j] = proof[i].finalEvalProof[j].Marshal()
			}
		}
		// the verifier checks a single claim about input wires itself
		claims.deleteClaim(wire)
	}

	return proof, nil
}

// Verify the consistency of the claimed output with the claimed input
// Unlike in Prove, the assignment argument need not be complete
func Verify(c Circuit, assignment WireAssignment, proof Proof, transcriptSettings fiatshamir.Settings, options ...Option) error {
	o, err := setup(c, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}
	defer o.workers.Stop()

	claims := newClaimsManager(c, assignment, o)

	var firstChallenge []fr.Element
	firstChallenge, err = getChallenges(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return err
	}

	wirePrefix := o.transcriptPrefix + "w"
	var baseChallenge [][]byte
	for i := len(c) - 1; i >= 0; i-- {
		wire := o.sorted[i]

		if wire.IsOutput() {
			claims.add(wire, firstChallenge, assignment[wire].Evaluate(firstChallenge, claims.memPool))
		}

		proofW := proof[i]
		claim := claims.getLazyClaim(wire)
		if wire.noProof() { // input wires with one claim only
			// make sure the proof is empty
			if len(proofW.finalEvalProof) != 0 || len(proofW.partialSumPolys) != 0 {
				return errors.New("no proof allowed for input wire with a single claim")
			}

			if wire.NbClaims() == 1 { // input wire
				// simply evaluate and see if it matches
				evaluation := assignment[wire].Evaluate(claim.evaluationPoints[0], claims.memPool)
				if !claim.claimedEvaluations[0].Equal(&evaluation) {
					return errors.New("incorrect input wire claim")
				}
			}
		} else if err = sumcheckVerify(
			claim, proof[i], fiatshamir.WithTranscript(o.transcript, wirePrefix+strconv.Itoa(i)+".", baseChallenge...),
		); err == nil { // incorporate prover claims about w's input into the transcript
			baseChallenge = make([][]byte, len(proofW.finalEvalProof))
			for j := range baseChallenge {
				baseChallenge[j] = proofW.finalEvalProof[j].Marshal()
			}
		} else {
			return fmt.Errorf("sumcheck proof rejected: %v", err) //TODO: Any polynomials to dump?
		}
		claims.deleteClaim(wire)
	}
	return nil
}

// outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsList(c Circuit, indexes map[*Wire]int) [][]int {
	idGate := GetGate("identity")
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].nbUniqueOutputs = 0
		if c[i].IsInput() {
			c[i].Gate = idGate
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
func (a WireAssignment) Complete(c Circuit) WireAssignment {

	sortedWires := topologicalSort(c)
	nbInstances := a.NumInstances()
	maxNbIns := 0

	for _, w := range sortedWires {
		maxNbIns = max(maxNbIns, len(w.Inputs))
		if a[w] == nil {
			a[w] = make([]fr.Element, nbInstances)
		}
	}

	// TODO: Parallelize, if needed
	ins := make([]fr.Element, maxNbIns)
	for i := range nbInstances {
		for _, w := range sortedWires {
			if !w.IsInput() {
				for inI, in := range w.Inputs {
					ins[inI] = a[in][i]
				}
				a[w][i] = w.Gate.Evaluate(ins[:len(w.Inputs)]...)
			}
		}
	}

	return a
}

func (a WireAssignment) NumInstances() int {
	for _, aW := range a {
		return len(aW)
	}
	panic("empty assignment")
}

func (a WireAssignment) NumVars() int {
	for _, aW := range a {
		return aW.NumVars()
	}
	panic("empty assignment")
}

// SerializeToBigInts flattens a proof object into the given slice of big.Ints
// useful in gnark hints.
func (p Proof) SerializeToBigInts(outs []*big.Int) error {
	offset := 0
	for i := range p {
		for _, poly := range p[i].partialSumPolys {
			frToBigInts(outs[offset:], poly)
			offset += len(poly)
		}
		if p[i].finalEvalProof != nil {
			frToBigInts(outs[offset:], p[i].finalEvalProof)
			offset += len(p[i].finalEvalProof)
		}
	}
	if offset != len(outs) {
		return fmt.Errorf("expected %d elements, got %d", offset, len(outs))
	}
	return nil
}

func frToBigInts(dst []*big.Int, src []fr.Element) {
	for i := range src {
		src[i].BigInt(dst[i])
	}
}
