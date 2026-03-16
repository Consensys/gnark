package gkr

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/std/hash"
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
	foldingCoeff       frontend.Variable
	levelI             int
	schedule           constraint.GkrProvingSchedule
	circuit            Circuit
	assignment         WireAssignment
	outgoingEvalPoints [][][]frontend.Variable // [levelI][outgoingClaimI] → eval point
	proof              Proof
	nbVars             int
}

func (e *zeroCheckLazyClaims) varsNum() int {
	return e.nbVars
}

func (e *zeroCheckLazyClaims) degree(int) int {
	return e.circuit.ZeroCheckDegree(e.schedule[e.levelI].(constraint.GkrSumcheckLevel))
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
	e.outgoingEvalPoints[e.levelI] = [][]frontend.Variable{r}
	level := e.schedule[e.levelI]
	perWireInputEvals := gkrcore.ReduplicateInputs(level, e.circuit, uniqueInputEvaluations)

	var terms []frontend.Variable
	flatW := 0
	for _, group := range level.ClaimGroups() {
		for _, wI := range group.Wires {
			wire := e.circuit[wI]

			var gateEval frontend.Variable
			if wire.IsInput() {
				gateEval = e.assignment[wI].Evaluate(api, r)
			} else {
				gateEval = wire.Gate.Evaluate(FrontendAPIWrapper{api}, perWireInputEvals[flatW]...)
			}

			for _, src := range group.ClaimSources {
				eq := polynomial.EvalEq(api, e.outgoingEvalPoints[src.Level][src.OutgoingClaimIndex], r)
				term := api.Mul(eq, gateEval)
				terms = append(terms, term)
			}
			flatW++
		}
	}

	claimedEvals := polynomial.Polynomial(terms)
	total := claimedEvals.Eval(api, e.foldingCoeff)
	api.AssertIsEqual(total, purportedValue)
	return nil
}

// transcript is a Fiat-Shamir transcript backed by a running hash.
// Field elements are written via bind; challenges are derived via getChallenge.
// The hash is never reset — all previous data is implicitly part of future challenges.
type transcript struct {
	h     hash.FieldHasher
	bound bool
}

func (t *transcript) bind(elements ...frontend.Variable) {
	if len(elements) == 0 {
		return
	}
	t.h.Write(elements...)
	t.bound = true
}

func (t *transcript) getChallenge(bindings ...frontend.Variable) frontend.Variable {
	t.bind(bindings...)
	if !t.bound {
		t.h.Write(0) // separator to prevent repeated values
	}
	t.bound = false
	return t.h.Sum()
}

// Verify the consistency of the claimed output with the claimed input.
// Unlike in Prove, the assignment argument need not be complete.
func Verify(api frontend.API, c Circuit, schedule constraint.GkrProvingSchedule, assignment WireAssignment, proof Proof, h hash.FieldHasher) error {
	nbVars := assignment.NbVars()
	if 1<<nbVars != assignment.NbInstances() {
		return errors.New("number of instances must be a power of 2")
	}

	t := &transcript{h: h}

	uniqueInputIndices := c.UniqueInputIndices(schedule)
	outgoingEvalPoints := make([][][]frontend.Variable, len(schedule)+1)
	initialChallengeI := len(schedule)

	firstChallenge := make([]frontend.Variable, nbVars)
	for j := range nbVars {
		firstChallenge[j] = t.getChallenge()
	}
	outgoingEvalPoints[initialChallengeI] = [][]frontend.Variable{firstChallenge}

	for levelI := len(schedule) - 1; levelI >= 0; levelI-- {
		level := schedule[levelI]

		if skipLevel, isSkip := level.(constraint.GkrSkipLevel); isSkip {
			outPoints := make([][]frontend.Variable, level.NbOutgoingEvalPoints())
			for k, src := range skipLevel.ClaimSources {
				outPoints[k] = outgoingEvalPoints[src.Level][src.OutgoingClaimIndex]
			}
			outgoingEvalPoints[levelI] = outPoints
		} else {
			nbClaims := level.NbClaims()

			foldingCoeff := frontend.Variable(0)
			if nbClaims >= 2 {
				foldingCoeff = t.getChallenge()
			}

			var claimedEvals []frontend.Variable
			for _, group := range level.ClaimGroups() {
				for _, wI := range group.Wires {
					for claimI, src := range group.ClaimSources {
						var claimedEval frontend.Variable
						if src.Level == initialChallengeI {
							claimedEval = assignment[wI].Evaluate(api, outgoingEvalPoints[src.Level][src.OutgoingClaimIndex])
						} else {
							idx := schedule[src.Level].FinalEvalProofIndex(uniqueInputIndices[wI][claimI], src.OutgoingClaimIndex)
							claimedEval = proof[src.Level].FinalEvalProof[idx]
						}
						claimedEvals = append(claimedEvals, claimedEval)
					}
				}
			}
			claimedSum := polynomial.Polynomial(claimedEvals).Eval(api, foldingCoeff)

			lazyClaims := &zeroCheckLazyClaims{
				foldingCoeff:       foldingCoeff,
				levelI:             levelI,
				schedule:           schedule,
				circuit:            c,
				assignment:         assignment,
				outgoingEvalPoints: outgoingEvalPoints,
				proof:              proof,
				nbVars:             nbVars,
			}

			if err := verifySumcheck(
				api, lazyClaims, proof[levelI], claimedSum,
				c.ZeroCheckDegree(level.(constraint.GkrSumcheckLevel)),
				t,
			); err != nil {
				return fmt.Errorf("sumcheck proof rejected at level %d: %v", levelI, err)
			}
		}

		t.bind(proof[levelI].FinalEvalProof...)
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
	for _, level := range schedule {
		nbUniqueInputs := len(circuit.UniqueGateInputs(level))
		if _, isSkip := level.(constraint.GkrSkipLevel); isSkip {
			serializedProofLen -= nbUniqueInputs * level.NbOutgoingEvalPoints()
		} else {
			perVar += circuit.ZeroCheckDegree(level.(constraint.GkrSumcheckLevel))
			serializedProofLen -= nbUniqueInputs
		}
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
	for levelI, level := range schedule {
		nbUniqueInputs := len(circuit.UniqueGateInputs(level))
		if _, isSkip := level.(constraint.GkrSkipLevel); isSkip {
			proof[levelI].FinalEvalProof = reader.nextN(nbUniqueInputs * level.NbOutgoingEvalPoints())
		} else {
			degree := circuit.ZeroCheckDegree(level.(constraint.GkrSumcheckLevel))
			proof[levelI].PartialSumPolys = make([]polynomial.Polynomial, logNbInstances)
			for j := range proof[levelI].PartialSumPolys {
				proof[levelI].PartialSumPolys[j] = reader.nextN(degree)
			}
			proof[levelI].FinalEvalProof = reader.nextN(nbUniqueInputs)
		}
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
