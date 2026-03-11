package gkr

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
)

// Type aliases for gadget circuit types
type (
	Wire    = gkrcore.GadgetWire
	Circuit = gkrcore.GadgetCircuit
)

// WireAssignment is an assignment of values to the same wire across many instances of the circuit
type WireAssignment []polynomial.MultiLin

func (a WireAssignment) NbInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignment) NbVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

// A SNARK gadget capable of verifying a GKR proof
// The goal is to prove/verify evaluations of many instances of the same circuit.

type Proof []sumcheckProof // for each schedule level, a sumcheck proof

// zeroCheckLazyClaims is a lazy claim for sumcheck (verifier side).
// It checks that the polynomial ∑ᵢ cⁱ eq(-, xᵢ) wᵢ(-) sums to the expected value,
// where the sum runs over all (wire v, claim source s) pairs in the level.
type zeroCheckLazyClaims struct {
	foldingCoeff  frontend.Variable
	levelI        int
	schedule      constraint.GkrProvingSchedule
	circuit       Circuit
	assignment    WireAssignment
	levelPoints   [][]frontend.Variable // [stepI] → eval point r
	evalPositions [][]int               // [wireI][evalI] → position in source level's finalEvalProof
	proof         Proof
	nbVars        int
}

func (e *zeroCheckLazyClaims) varsNum() int {
	return e.nbVars
}

func (e *zeroCheckLazyClaims) degree(int) int {
	return gkrcore.Degree(e.schedule[e.levelI].(constraint.GkrSumcheckLevel), e.circuit)
}

// verifyFinalEval finalizes the verification of a level at the sumcheck evaluation point r.
// The sumcheck protocol has already reduced the per-wire claims to verifying
// ∑ᵢ cⁱ eq(xᵢ, r) · wᵢ(r) = purportedValue, where the sum runs over all
// claims on each wire and c is foldingCoeff.
// Both purportedValue and the vector r have been randomized during sumcheck.
//
// For input wires, w(r) is computed directly from the assignment.
// For non-input wires, the prover claims evaluations of the input wires at r,
// communicated through uniqueInputEvaluations; those claims are verified later.
func (e *zeroCheckLazyClaims) verifyFinalEval(api frontend.API, r []frontend.Variable, purportedValue frontend.Variable, uniqueInputEvaluations []frontend.Variable) error {
	e.levelPoints[e.levelI] = r
	level := e.schedule[e.levelI].(constraint.GkrSumcheckLevel)
	perWireInputEvals := gkrcore.ReduplicateInputs(level, e.circuit, uniqueInputEvaluations)

	var terms []frontend.Variable
	flatW := 0
	for _, group := range level {
		for _, wI := range group.Wires {
			wire := e.circuit[wI]

			var gateEval frontend.Variable
			if wire.IsInput() {
				gateEval = e.assignment[wI].Evaluate(api, r)
			} else {
				gateEval = wire.Gate.Evaluate(FrontendAPIWrapper{api}, perWireInputEvals[flatW]...)
			}

			for _, src := range group.ClaimSources {
				eq := polynomial.EvalEq(api, e.levelPoints[src], r)
				term := api.Mul(eq, gateEval)
				terms = append(terms, term)
			}
			flatW++
		}
	}

	ys := polynomial.Polynomial(terms)
	total := ys.Eval(api, e.foldingCoeff)
	api.AssertIsEqual(total, purportedValue)
	return nil
}

type settings struct {
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
}

type Option func(*settings)

func setup(api frontend.API, c Circuit, schedule constraint.GkrProvingSchedule, assignment WireAssignment, transcriptSettings fiatshamir.Settings, options ...Option) (settings, error) {
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

	if transcriptSettings.Transcript == nil {
		challengeNames := ChallengeNames(c, schedule, o.nbVars, transcriptSettings.Prefix)
		o.transcript = fiatshamir.NewTranscript(api, transcriptSettings.Hash, challengeNames)
		if err = o.transcript.Bind(challengeNames[0], transcriptSettings.BaseChallenges); err != nil {
			return o, err
		}
	} else {
		o.transcript, o.transcriptPrefix = transcriptSettings.Transcript, transcriptSettings.Prefix
	}

	return o, err
}

func ChallengeNames(c Circuit, schedule constraint.GkrProvingSchedule, logNbInstances int, prefix string) []string {
	var challenges []string

	// First challenge: fC.0 ... fC.(n-1)
	firstChallengePrefix := prefix + "fC."
	for j := 0; j < logNbInstances; j++ {
		challenges = append(challenges, firstChallengePrefix+strconv.Itoa(j))
	}

	// Per sumcheck level (in reverse order to match Verify iteration)
	for levelI := len(schedule) - 1; levelI >= 0; levelI-- {
		s, ok := schedule[levelI].(constraint.GkrSumcheckLevel)
		if !ok {
			continue
		}
		levelPrefix := prefix + "l" + strconv.Itoa(levelI) + "."

		if gkrcore.NbClaims(s) >= 2 {
			challenges = append(challenges, levelPrefix+"fold")
		}

		pSPPrefix := levelPrefix + "pSP."
		for k := 0; k < logNbInstances; k++ {
			challenges = append(challenges, pSPPrefix+strconv.Itoa(k))
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

// Verify the consistency of the claimed output with the claimed input.
// Unlike in Prove, the assignment argument need not be complete.
func Verify(api frontend.API, c Circuit, schedule constraint.GkrProvingSchedule, assignment WireAssignment, proof Proof, transcriptSettings fiatshamir.Settings, options ...Option) error {
	o, err := setup(api, c, schedule, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}

	evalPositions := gkrcore.BuildFinalEvalPositions(schedule, c)
	levelPoints := make([][]frontend.Variable, len(schedule)+1)
	initialChallengeI := len(schedule)

	var firstChallenge []frontend.Variable
	firstChallenge, err = getChallenges(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return err
	}
	levelPoints[initialChallengeI] = firstChallenge

	var baseChallenge []frontend.Variable
	for levelI := len(schedule) - 1; levelI >= 0; levelI-- {
		switch s := schedule[levelI].(type) {
		case constraint.GkrSkipLevel:
			levelPoints[levelI] = levelPoints[s.ClaimSources[0]]

		case constraint.GkrSumcheckLevel:
			nbClaims := gkrcore.NbClaims(s)
			levelPrefix := o.transcriptPrefix + "l" + strconv.Itoa(levelI) + "."

			foldingCoeff := frontend.Variable(0)
			if nbClaims >= 2 {
				foldName := levelPrefix + "fold"
				if err = o.transcript.Bind(foldName, baseChallenge); err != nil {
					return err
				}
				if foldingCoeff, err = o.transcript.ComputeChallenge(foldName); err != nil {
					return err
				}
				baseChallenge = nil
			}

			// Collect y-values
			var ys []frontend.Variable
			for _, group := range s {
				for _, wI := range group.Wires {
					evalI := 0
					for _, src := range group.ClaimSources {
						var y frontend.Variable
						if src == initialChallengeI {
							y = assignment[wI].Evaluate(api, levelPoints[src])
						} else {
							y = proof[src].FinalEvalProof[evalPositions[wI][evalI]]
							evalI++
						}
						ys = append(ys, y)
					}
				}
			}

			ysPoly := polynomial.Polynomial(ys)
			claimedSum := ysPoly.Eval(api, foldingCoeff)

			lazyClaims := &zeroCheckLazyClaims{
				foldingCoeff:  foldingCoeff,
				levelI:        levelI,
				schedule:      schedule,
				circuit:       c,
				assignment:    assignment,
				levelPoints:   levelPoints,
				evalPositions: evalPositions,
				proof:         proof,
				nbVars:        o.nbVars,
			}

			var scBaseChallenges []frontend.Variable
			if nbClaims < 2 {
				scBaseChallenges = baseChallenge
			}

			if err = verifySumcheck(
				api, lazyClaims, proof[levelI], claimedSum,
				gkrcore.Degree(s, c),
				fiatshamir.WithTranscript(o.transcript, levelPrefix, scBaseChallenges...),
			); err != nil {
				return fmt.Errorf("sumcheck proof rejected at level %d: %v", levelI, err)
			}

			baseChallenge = proof[levelI].FinalEvalProof
		}
	}
	return nil
}

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
		panic("bug")
	}
	return res
}

// ComputeLogNbInstances derives n such that the number of instances is 2ⁿ
// from the size of the proof and the circuit/schedule structure.
func ComputeLogNbInstances(circuit Circuit, schedule constraint.GkrProvingSchedule, serializedProofLen int) int {
	perVar := 0
	for _, step := range schedule {
		s, ok := step.(constraint.GkrSumcheckLevel)
		if !ok {
			continue
		}
		perVar += gkrcore.Degree(s, circuit)
		serializedProofLen -= len(gkrcore.UniqueGateInputs(s, circuit))
	}
	if perVar == 0 {
		if serializedProofLen == 0 {
			return -1
		}
	} else {
		res := serializedProofLen / perVar
		if res*perVar == serializedProofLen {
			return res
		}
	}

	panic("cannot compute logNbInstances")
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

func DeserializeProof(circuit Circuit, schedule constraint.GkrProvingSchedule, serializedProof []frontend.Variable) (Proof, error) {
	proof := make(Proof, len(schedule))
	logNbInstances := ComputeLogNbInstances(circuit, schedule, len(serializedProof))

	reader := variablesReader(serializedProof)
	for levelI, step := range schedule {
		s, ok := step.(constraint.GkrSumcheckLevel)
		if !ok {
			continue
		}
		degree := gkrcore.Degree(s, circuit)
		proof[levelI].PartialSumPolys = make([]polynomial.Polynomial, logNbInstances)
		for j := range proof[levelI].PartialSumPolys {
			proof[levelI].PartialSumPolys[j] = reader.nextN(degree)
		}
		proof[levelI].FinalEvalProof = reader.nextN(len(gkrcore.UniqueGateInputs(s, circuit)))
	}
	if reader.hasNextN(1) {
		return nil, fmt.Errorf("proof too long: expected %d encountered %d", len(serializedProof)-len(reader), len(serializedProof))
	}
	return proof, nil
}

type FrontendAPIWrapper struct {
	frontend.API
}

func (api FrontendAPIWrapper) SumExp17(a, b, c frontend.Variable) frontend.Variable {
	i := api.Add(a, b, c)
	res := api.Mul(i, i)    // i^2
	res = api.Mul(res, res) // i^4
	res = api.Mul(res, res) // i^8
	res = api.Mul(res, res) // i^16
	return api.Mul(res, i)  // i^17
}
