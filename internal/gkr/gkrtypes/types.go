package gkrtypes

import (
	"errors"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

type (
	InputDependency struct {
		OutputWire     int
		OutputInstance int
		InputInstance  int
	}

	GateID           uint16
	SerializableWire struct {
		Gate   GateID
		Inputs []int
	}
	SerializableCircuit []SerializableWire

	// A Gate is a low-degree multivariate polynomial
	Gate[GateExecutable any] struct {
		Evaluate    GateExecutable
		NbIn        int // number of inputs
		Degree      int // total Degree of the polynomial
		SolvableVar int // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
	}

	Wire[GateExecutable any] struct {
		Gate            *Gate[GateExecutable]
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

	// Registered types (with both bytecode and SNARK-friendly executables)
	RegisteredGate    = Gate[BothExecutables]
	RegisteredCircuit = Circuit[BothExecutables]
	RegisteredWire    = Wire[BothExecutables]
	RegisteredWires   = Wires[BothExecutables]

	// Executable types (bytecode only, for native proving)
	ExecutableCircuit = Circuit[*GateBytecode]
	ExecutableWire    = Wire[*GateBytecode]
	ExecutableWires   = Wires[*GateBytecode]

	// Gadget types (gate functions only, for in-circuit verification)
	GadgetCircuit = Circuit[gkr.GateFunction]
	GadgetWire    = Wire[gkr.GateFunction]
	GadgetWires   = Wires[gkr.GateFunction]
)

// NewGate creates a new gate function with the given parameters:
// - f: the polynomial function defining the gate
// - compiled: the compiled form of the gate function
// - NbIn: number of inputs to the gate
// - Degree: total Degree of the polynomial. In case of multivariate polynomials, it is the maximum Degree over all terms.
// - SolvableVar: if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
// - Curves: Curves that the gate is allowed to be used over
func NewGate(f gkr.GateFunction, compiled *GateBytecode, nbIn int, degree int, solvableVar int, curves []ecc.ID) *RegisteredGate {

	return &RegisteredGate{
		Evaluate: BothExecutables{
			Bytecode:      compiled,
			SnarkFriendly: f,
		},
		NbIn:        nbIn,
		Degree:      degree,
		SolvableVar: solvableVar,
	}
}

func (be BothExecutables) getGateFunction() gkr.GateFunction {
	return be.SnarkFriendly
}

func (be BothExecutables) getByteCode() *GateBytecode {
	return be.Bytecode
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

func (c Circuit[GateExecutable]) setNbUniqueOutputs() {

	for i := range c {
		c[i].NbUniqueOutputs = 0
	}

	curWireIn := make([]bool, len(c))
	uniqueIns := make([]int, 0, len(c))
	for i := range c {
		// clear the caches
		for j := range uniqueIns {
			curWireIn[uniqueIns[j]] = false
		}
		uniqueIns = uniqueIns[:0]

		// count!
		for _, in := range c[i].Inputs {
			if !curWireIn[in] {
				c[in].NbUniqueOutputs++
				curWireIn[in] = true
				uniqueIns = append(uniqueIns, in)
			}
		}
	}
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

var ErrZeroFunction = errors.New("detected a zero function")

// some sample gates

// Identity gate: x -> x
func Identity() *RegisteredGate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return in[0]
	}, &GateBytecode{}, 1, 1, 0, gnark.Curves())
}

// Add2 gate: (x, y) -> x + y
func Add2() *RegisteredGate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Add(in[0], in[1])
	}, &GateBytecode{
		Instructions: []GateInstruction{{
			Op:     OpAdd,
			Inputs: []uint16{0, 1},
		}},
	}, 2, 1, 0, gnark.Curves())
}

// Sub2 gate: (x, y) -> x - y
func Sub2() *RegisteredGate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Sub(in[0], in[1])
	}, &GateBytecode{
		Instructions: []GateInstruction{{
			Op:     OpSub,
			Inputs: []uint16{0, 1},
		}},
	}, 2, 1, 0, gnark.Curves())
}

// Neg gate: x -> -x
func Neg() *RegisteredGate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Neg(in[0])
	}, &GateBytecode{
		Instructions: []GateInstruction{{
			Op:     OpNeg,
			Inputs: []uint16{0},
		}},
	}, 1, 1, 0, gnark.Curves())
}

// Mul2 gate: (x, y) -> x * y
func Mul2() *RegisteredGate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Mul(in[0], in[1])
	}, &GateBytecode{
		Instructions: []GateInstruction{{
			Op:     OpMul,
			Inputs: []uint16{0, 1},
		}},
	}, 2, 2, -1, gnark.Curves())
}

func ConvertGate[GateExecutable, TargetGateExecutable any](g *Gate[GateExecutable], converter func(GateExecutable) TargetGateExecutable) *Gate[TargetGateExecutable] {
	return &Gate[TargetGateExecutable]{
		Evaluate:    converter(g.Evaluate),
		NbIn:        g.NbIn,
		Degree:      g.Degree,
		SolvableVar: g.SolvableVar,
	}
}

func ConvertCircuit[GateExecutable, TargetGateExecutable any](c Circuit[GateExecutable], gateConverter func(GateExecutable) TargetGateExecutable) Circuit[TargetGateExecutable] {
	res := make(Circuit[TargetGateExecutable], len(c))
	for i := range c {
		res[i] = Wire[TargetGateExecutable]{
			Gate:            ConvertGate(c[i].Gate, gateConverter),
			Inputs:          c[i].Inputs,
			NbUniqueOutputs: c[i].NbUniqueOutputs,
		}
	}

	return res
}

// ToExecutable converts a registered circuit (with both executables) to an executable circuit (bytecode only).
func ToExecutable(c RegisteredCircuit) ExecutableCircuit {
	return ConvertCircuit(c, BothExecutables.getByteCode)
}

func ToExecutableGate(g *RegisteredGate) *Gate[*GateBytecode] {
	return ConvertGate(g, BothExecutables.getByteCode)
}

func ToGadgetGate(g *RegisteredGate) *Gate[gkr.GateFunction] {
	return ConvertGate(g, BothExecutables.getGateFunction)
}

// ToGadget converts a registered circuit (with both executables) to a gadget circuit (gate functions only, for in-circuit verification).
func ToGadget(c RegisteredCircuit) GadgetCircuit {
	return ConvertCircuit(c, func(e BothExecutables) gkr.GateFunction {
		return e.SnarkFriendly
	})
}
