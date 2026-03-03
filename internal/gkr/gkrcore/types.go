package gkrcore

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

type (
	InputDependency struct {
		OutputWire     int
		OutputInstance int
		InputInstance  int
	}

	// RawWire is a minimal wire representation with only inputs and gate function.
	RawWire struct {
		Gate     gkr.GateFunction
		Inputs   []int
		Exported bool
	}

	// RawCircuit is a minimal circuit representation for API-level circuit construction.
	// It contains only the essential topology (inputs) and gate functions.
	RawCircuit []RawWire

	// A Gate is a low-degree multivariate polynomial
	Gate[GateExecutable any] struct {
		Evaluate    GateExecutable
		NbIn        int // number of inputs
		Degree      int // total Degree of the polynomial
		SolvableVar int // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
	}

	Wire[GateExecutable any] struct {
		Gate            Gate[GateExecutable]
		Inputs          []int
		NbUniqueOutputs int
		Exported        bool
	}

	Circuit[GateExecutable any] []Wire[GateExecutable]

	// Type aliases for different circuit instantiations

	// Serializable types (bytecode only, for native proving)

	SerializableGate    = Gate[GateBytecode]
	SerializableCircuit = Circuit[GateBytecode]
	SerializableWire    = Wire[GateBytecode]

	// Gadget types (gate functions only, for in-circuit verification)

	GadgetGate    = Gate[gkr.GateFunction]
	GadgetCircuit = Circuit[gkr.GateFunction]
	GadgetWire    = Wire[gkr.GateFunction]
)

// IsInput returns whether the wire is an input wire.
func (w Wire[GateExecutable]) IsInput() bool {
	return len(w.Inputs) == 0
}

// IsOutput returns whether the wire is an output wire. A wire is an output wire
// if it is not input to any other wire.
func (w Wire[GateExecutable]) IsOutput() bool {
	return w.NbUniqueOutputs == 0 || w.Exported
}

// NbClaims returns the number of claims to be proven about this wire. The number
// of claims is the number of Wires it is input to, except for an output wire, which
// has an extra claim.
func (w Wire[GateExecutable]) NbClaims() int {
	res := w.NbUniqueOutputs
	if w.IsOutput() {
		res++
	}
	return res
}

// NoProof returns whether no proof is needed for this wire. This corresponds
// to input wires without any claims to be made about them.
func (w Wire[GateExecutable]) NoProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

// NbUniqueInputs returns the number of unique input wires to this wire.
func (w Wire[GateExecutable]) NbUniqueInputs() int {
	set := make(map[int]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

// ZeroCheckDegree returns the degree in each variable of the zero-check polynomial
// associated with this gate, if any. If this wire is not subject to zero-check, it will return 0.
func (w Wire[GateExecutable]) ZeroCheckDegree() int {
	if w.IsInput() {
		switch w.NbClaims() {
		case 0:
			panic("should be unreachable")
		case 1:
			return 0
		default:
			// Input gate with multiple claims treated as a degree 1 gate.
			return 2
		}
	}
	return w.Gate.Degree + 1
}

// ClaimPropagationInfo returns sets of indices describing the pruning of claim propagation.
// At the end of sumcheck for wire #wireIndex, we end up with sequences "uniqueEvaluations" and "evaluations",
// the former a subsequence of the latter.
// injection are the indices of the unique evaluations in the original evaluation list.
// injectionRightInverse are the indices of the original evaluations in the unique evaluations list.
// There are no guarantees on the non-unique choice of the semi-inverse map.
func (c Circuit[GateExecutable]) ClaimPropagationInfo(wireIndex int) (injection, injectionLeftInverse []int) {
	w := c[wireIndex]
	indexInProof := makeNeg1Slice(len(c)) // O(n); use a map instead if it caused performance issues
	injection = make([]int, 0, len(w.Inputs))
	injectionLeftInverse = make([]int, len(w.Inputs))

	for inI, in := range w.Inputs {
		if indexInProof[in] == -1 { // not found
			indexInProof[in] = len(injection)
			injection = append(injection, inI)
		}
		injectionLeftInverse[inI] = indexInProof[in]
	}

	return
}

func (c Circuit[GateExecutable]) maxGateDegree() int {
	res := 1
	for i := range c {
		if !c[i].IsInput() {
			res = max(res, c[i].Gate.Degree)
		}
	}
	return res
}

// MemoryRequirements returns an increasing vector of memory allocation sizes required for proving a GKR statement
func (c Circuit[GateExecutable]) MemoryRequirements(nbInstances int) []int {
	res := []int{256, nbInstances, nbInstances * (c.maxGateDegree() + 1)}

	if res[0] > res[1] { // make sure it's sorted
		res[0], res[1] = res[1], res[0]
		if res[1] > res[2] {
			res[1], res[2] = res[2], res[1]
		}
	}

	return res
}

// OutputsList for each wire, returns the set of indexes of wires it is input to.
// It also sets the NbUniqueOutputs fields.
func (c Circuit[GateExecutable]) OutputsList() [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].NbUniqueOutputs = 0
	}
	ins := make(map[int]struct{}, len(c))
	for i := range c {
		for k := range ins { // clear map
			delete(ins, k)
		}
		for _, in := range c[i].Inputs {
			res[in] = append(res[in], i)
			if _, ok := ins[in]; !ok {
				c[in].NbUniqueOutputs++
				ins[in] = struct{}{}
			}
		}
	}
	return res
}

// Inputs returns the list of input wire indices.
func (c Circuit[GateExecutable]) Inputs() []int {
	res := make([]int, 0, len(c))
	for i := range c {
		if c[i].IsInput() {
			res = append(res, i)
		}
	}
	return res
}

// Outputs returns the list of output wire indices.
// It requires the NbUniqueOutput values to have been set.
func (c Circuit[GateExecutable]) Outputs() []int {
	res := make([]int, 0, len(c))
	for i := range c {
		if c[i].IsOutput() {
			res = append(res, i)
		}
	}
	return res
}

// MaxGateNbIn returns the maximum number of inputs of any gate in the circuit.
func (c Circuit[GateExecutable]) MaxGateNbIn() int {
	res := 0
	for i := range c {
		res = max(res, len(c[i].Inputs))
	}
	return res
}

// ProofSize computes how large the proof for a circuit would be. It needs NbUniqueOutputs to be set.
func (c Circuit[GateExecutable]) ProofSize(logNbInstances int) int {
	nbUniqueInputs := 0
	nbPartialEvalPolys := 0
	for i := range c {
		nbUniqueInputs += c[i].NbUniqueOutputs // each unique output is manifest in a finalEvalProof entry
		nbPartialEvalPolys += c[i].ZeroCheckDegree()
	}
	return nbUniqueInputs + nbPartialEvalPolys*logNbInstances
}

// makeNeg1Slice returns a slice of size n with all elements set to -1.
func makeNeg1Slice(n int) []int {
	res := make([]int, n)
	for i := range res {
		res[i] = -1
	}
	return res
}

// some sample gates

// Identity gate: x -> x
func Identity(_ gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return in[0]
}

// Add2 gate: (x, y) -> x + y
func Add2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Add(in[0], in[1])
}

// Sub2 gate: (x, y) -> x - y
func Sub2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Sub(in[0], in[1])
}

// Neg gate: x -> -x
func Neg(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Neg(in[0])
}

// Mul2 gate: (x, y) -> x * y
func Mul2(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return api.Mul(in[0], in[1])
}

// BlueprintSolve is the interface for GKR solve blueprints
type BlueprintSolve interface {
	constraint.BlueprintStateful[constraint.U64]
	SetNbInstances(nbInstances uint32)
}

// Blueprints holds all GKR-related blueprint IDs and references
type Blueprints struct {
	SolveID         constraint.BlueprintID
	Solve           BlueprintSolve
	ProveID         constraint.BlueprintID
	GetAssignmentID constraint.BlueprintID
}

// ProvingSchedule types for GKR proving
// These define how claims are grouped and processed during the proving protocol.

type (
	// ClaimGroup represents a set of wires with their claim sources.
	// It is agnostic of the protocol - it only describes which wires have claims
	// from which sources, not what to do with them.
	ClaimGroup struct {
		Wires        []int `json:"wires"`
		ClaimSources []int `json:"claimSources"` // indices of steps that produced these claims
	}

	// ProvingStep is the interface for a single step in the proving schedule.
	// A step is either a SkipStep or a SumcheckStep.
	ProvingStep interface {

	}

	// SkipStep represents a step where zerocheck is skipped.
	// Claims propagate through at their existing evaluation points.
	SkipStep ClaimGroup

	// SumcheckStep represents a step where one or more zerochecks are batched
	// together in a single sumcheck. Each ClaimGroup within may have different
	// claim sources (sumcheck-level batching), or the same source (enabling
	// zerocheck-level batching with shared eq tables).
	SumcheckStep []ClaimGroup

	// ProvingSchedule is a sequence of steps defining how to prove a GKR circuit.
	ProvingSchedule []ProvingStep
)

// DefaultProvingSchedule generates a simple schedule for a circuit where each non-input
// wire gets its own sumcheck step, processed in reverse topological order.
// This matches the original GKR prover behavior before schedule support was added.
func DefaultProvingSchedule[T any](c Circuit[T]) ProvingSchedule {
	var steps ProvingSchedule
	wireToStep := make(map[int]int) // wire -> step index that processes it

	// Process wires in reverse order (outputs first)
	for i := len(c) - 1; i >= 0; i-- {
		if c[i].IsInput() {
			continue
		}

		stepI := len(steps)

		// Collect claim sources from input wires
		var claimSources []int
		seen := make(map[int]bool)
		for _, inputWire := range c[i].Inputs {
			if srcStep, ok := wireToStep[inputWire]; ok && !seen[srcStep] {
				claimSources = append(claimSources, srcStep)
				seen[srcStep] = true
			}
		}

		// For output wires, the initial claim comes from step -1 (the verifier's initial challenge)
		// We represent this as having no claim sources for output wires
		if c[i].IsOutput() && len(claimSources) == 0 {
			claimSources = nil // initial challenge, no prior step
		}

		steps = append(steps, SumcheckStep{
			ClaimGroup{
				Wires:        []int{i},
				ClaimSources: claimSources,
			},
		})

		wireToStep[i] = stepI
	}

	return steps
}

// Compile compiles a raw circuit into both a gadget circuit and a serializable circuit.
// It computes all wire and gate metadata (Degree, SolvableVar, NbUniqueOutputs).
func (c RawCircuit) Compile(mod *big.Int) (GadgetCircuit, SerializableCircuit, error) {
	gadget := make(GadgetCircuit, len(c))
	serializable := make(SerializableCircuit, len(c))

	// First pass: copy inputs, gates, and exported flags, compute NbUniqueOutputs
	curWireIn := make([]bool, len(c))
	for i := range c {
		gadget[i].Inputs = c[i].Inputs
		gadget[i].Exported = c[i].Exported
		serializable[i].Inputs = c[i].Inputs
		serializable[i].Exported = c[i].Exported

		// Compute NbUniqueOutputs for input wires
		for _, in := range c[i].Inputs {
			if !curWireIn[in] {
				gadget[in].NbUniqueOutputs++
				serializable[in].NbUniqueOutputs++
				curWireIn[in] = true
			}
		}
		// clear curWireIn for next iteration
		for _, in := range c[i].Inputs {
			curWireIn[in] = false
		}
	}

	// Second pass: compile gates and set metadata
	for i := range c {
		if len(c[i].Inputs) == 0 { // input wire
			if c[i].Gate != nil {
				return nil, nil, errors.New("nil gate expected for input wire")
			}
			continue
		}

		if c[i].Gate == nil {
			return nil, nil, errors.New("gate function required for non-input wire")
		}

		nbIn := len(c[i].Inputs)
		compiledGate, err := CompileGateFunction(c[i].Gate, nbIn, mod)
		if err != nil {
			return nil, nil, err
		}

		gadget[i].Gate = GadgetGate{
			Evaluate:    c[i].Gate,
			NbIn:        nbIn,
			Degree:      compiledGate.Degree,
			SolvableVar: compiledGate.SolvableVar,
		}
		serializable[i].Gate = compiledGate
	}

	return gadget, serializable, nil
}
