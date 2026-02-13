package gkrtypes

import (
	"math/big"
	"reflect"

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
	}

	Circuit[GateExecutable any] []Wire[GateExecutable]

	// Wires is a slice of pointers to Wire. It is used for propagating claim
	// information through the circuit.
	Wires[GateExecutable any] []*Wire[GateExecutable]

	BothExecutables struct {
		Bytecode      *GateBytecode
		SnarkFriendly gkr.GateFunction
	}

	// Type aliases for different circuit instantiations

	// Serializable types (bytecode only, for native proving)
	SerializableGate    = Gate[GateBytecode]
	SerializableCircuit = Circuit[GateBytecode]
	SerializableWire    = Wire[GateBytecode]
	SerializableWires   = Wires[GateBytecode]

	// Gadget types (gate functions only, for in-circuit verification)
	GadgetGate    = Gate[gkr.GateFunction]
	GadgetCircuit = Circuit[gkr.GateFunction]
	GadgetWire    = Wire[gkr.GateFunction]
	GadgetWires   = Wires[gkr.GateFunction]
)

func (be BothExecutables) getGateFunction() gkr.GateFunction {
	return be.SnarkFriendly
}

func (be BothExecutables) getByteCode() GateBytecode {
	return *be.Bytecode
}

// IsInput returns whether the wire is an input wire.
func (w Wire[GateExecutable]) IsInput() bool {
	return len(w.Inputs) == 0
}

// IsOutput returns whether the wire is an output wire. A wire is an output wire
// if it is not input to any other wire.
func (w Wire[GateExecutable]) IsOutput() bool {
	return w.NbUniqueOutputs == 0
}

// NbClaims returns the number of claims to be proven about this wire. The number
// of claims is the number of Wires it is input to. For output wires, there is always
// one claim to be made.
func (w Wire[GateExecutable]) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.NbUniqueOutputs
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

// ClaimPropagationInfo returns sets of indices describing the pruning of claim propagation.
// At the end of sumcheck for wire #wireIndex, we end up with sequences "uniqueEvaluations" and "evaluations",
// the former a subsequence of the latter.
// injection are the indices of the unique evaluations in the original evaluation list.
// injectionRightInverse are the indices of the original evaluations in the unique evaluations list.
// There are no guarantees on the non-unique choice of the semi-inverse map.
func (wires Wires[GateExecutable]) ClaimPropagationInfo(wireIndex int) (injection, injectionLeftInverse []int) {
	w := wires[wireIndex]
	indexInProof := makeNeg1Slice(len(wires)) // O(n); use a map instead if it caused performance issues
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
		if !c[i].NoProof() {
			nbPartialEvalPolys += c[i].Gate.Degree + 1
		}
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

type topSortData struct {
	outputs    [][]int
	status     []int // status > 0 indicates number of inputs left to be ready. status = 0 means ready. status = -1 means done
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

func (c Circuit[GateExecutable]) statusList() []int {
	res := make([]int, len(c))
	for i := range c {
		res[i] = len(c[i].Inputs)
	}
	return res
}

// TopologicalSort sorts the wires in order of dependence. Such that for any wire, any one it depends on
// occurs before it. It tries to stick to the input order as much as possible. An already sorted list will remain unchanged.
// It also sets the nbOutput flags, and a dummy IdentityGate for input wires.
// Worst-case inefficient O(n^2), but that probably won't matter since the circuits are small.
// Furthermore, it is efficient with already-close-to-sorted lists, which are the expected input
func (c Circuit[GateExecutable]) TopologicalSort() Wires[GateExecutable] {
	var data topSortData
	data.outputs = c.OutputsList()
	data.status = c.statusList()
	sorted := make(Wires[GateExecutable], len(c))

	for data.leastReady = 0; data.status[data.leastReady] != 0; data.leastReady++ {
	}

	for i := range c {
		sorted[i] = &c[data.leastReady]
		data.markDone(data.leastReady)
	}

	return sorted
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
	constraint.Blueprint
	SetNbInstances(nbInstances uint32)
}

// Blueprints holds all GKR-related blueprint IDs and references
type Blueprints struct {
	SolveID         constraint.BlueprintID
	Solve           BlueprintSolve
	ProveID         constraint.BlueprintID
	GetAssignmentID constraint.BlueprintID
}

// Compile converts a gadget circuit to a serializable circuit by compiling the gate functions.
// It also sets wire and gate metadata (Degree, SolvableVar, NbUniqueOutputs) for both the input and output circuits.
func (c GadgetCircuit) Compile(mod *big.Int) SerializableCircuit {

	for i := range c {
		c[i].NbUniqueOutputs = 0
	}

	// compile the gate and compute metadata
	curWireIn := make([]bool, len(c)) // curWireIn[j] = true iff i takes j as input.
	tester := gateTester{mod: mod}    // tester computes the gate's degree
	res := make(SerializableCircuit, len(c))
	var err error
	for i := range c {
		// Compute NbUniqueOutputs as we go.
		for j := range curWireIn {
			curWireIn[j] = false
		}

		// count!
		for _, in := range c[i].Inputs {
			if !curWireIn[in] {
				c[in].NbUniqueOutputs++
				curWireIn[in] = true
			}
		}

		if c[i].IsInput() {
			if !reflect.DeepEqual(c[i].Gate, GadgetGate{}) {
				panic("empty gate expected for input wire")
			}
			break
		}

		c[i].Gate.NbIn = len(c[i].Inputs)
		if res[i].Gate.Evaluate, err = CompileGateFunction(c[i].Gate.Evaluate, c[i].Gate.NbIn); err != nil {
			panic(err)
		}

		tester.setGate(res[i].Gate.Evaluate, c[i].Gate.NbIn)

		c[i].Gate.Degree = len(tester.fitPoly(res[i].Gate.Evaluate.EstimateDegree(len(c[i].Inputs)))) - 1
		if c[i].Gate.Degree == -1 {
			panic("cannot find degree for gate")
		}

		c[i].Gate.SolvableVar = -1
		for j := range c[i].Gate.NbIn {
			if tester.isAdditive(j) {
				c[i].Gate.SolvableVar = j
				break
			}
		}
	}

	// copy metadata from c to res
	for i := range c {
		res[i].Inputs = c[i].Inputs
		res[i].NbUniqueOutputs = c[i].NbUniqueOutputs
		res[i].Gate.Degree = c[i].Gate.Degree
		res[i].Gate.SolvableVar = c[i].Gate.SolvableVar
		res[i].Gate.NbIn = c[i].Gate.NbIn
	}

	return res
}
