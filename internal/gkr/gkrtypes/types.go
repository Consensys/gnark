package gkrtypes

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/polynomial"
)

// A Gate is a low-degree multivariate polynomial
type Gate struct {
	compiled    *CompiledGate // Compiled form of the gate
	nbIn        int           // number of inputs
	degree      int           // total degree of the polynomial
	solvableVar int           // if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
	curves      []ecc.ID      // curves that the gate is allowed to be used over
}

// NewGate creates a new gate function with the given parameters:
// - f: the polynomial function defining the gate
// - nbIn: number of inputs to the gate
// - degree: total degree of the polynomial. In case of multivariate polynomials, it is the maximum degree over all terms.
// - solvableVar: if there is a variable whose value can be uniquely determined from the value of the gate and the other inputs, its index, -1 otherwise
// - curves: curves that the gate is allowed to be used over
func NewGate(f gkr.GateFunction, nbIn int, degree int, solvableVar int, curves []ecc.ID) *Gate {
	// Compile the gate function immediately
	compiled := CompileGateFunction(f, nbIn, degree, solvableVar, curves)

	return &Gate{
		compiled:    compiled,
		nbIn:        nbIn,
		degree:      degree,
		solvableVar: solvableVar,
		curves:      curves,
	}
}

// SupportsCurve returns whether the gate can be used over the given curve.
func (g *Gate) SupportsCurve(curve ecc.ID) bool {
	return slices.Contains(g.curves, curve)
}

// Degree returns the total degree of the gate's polynomial e.g. Degree(xy²) = 3
func (g *Gate) Degree() int {
	return g.degree
}

// SolvableVar returns the index of a variable of degree 1 in the gate's
// polynomial. If there is no such variable, it returns -1.
func (g *Gate) SolvableVar() int {
	return g.solvableVar
}

// NbIn returns the number of inputs to the gate (its fan-in)
func (g *Gate) NbIn() int {
	return g.nbIn
}

// Compiled returns the compiled form of the gate.
func (g *Gate) Compiled() *CompiledGate {
	return g.compiled
}

// Wire represents a wire in the GKR circuit. A wire is defined through its gate
// and its inputs.
type Wire struct {
	Gate            *Gate
	Inputs          []int
	NbUniqueOutputs int
}

// IsInput returns whether the wire is an input wire.
func (w Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

// IsOutput returns whether the wire is an output wire. A wire is an output wire
// it it is not input to any other wire.
func (w Wire) IsOutput() bool {
	return w.NbUniqueOutputs == 0
}

// NbClaims returns the number of claims to be proven about this wire. The number
// of claims is the number of Wires it is input to. For output wires, there is always
// one claim to be made.
func (w Wire) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.NbUniqueOutputs
}

// NoProof returns whether no proof is needed for this wire. This corresponds
// to input wires without any claims to be made about them.
func (w Wire) NoProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

// NbUniqueInputs returns the number of unique input wires to this wire.
func (w Wire) NbUniqueInputs() int {
	set := make(map[int]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

// Circuit is a GKR circuit: a list of wires. The wires are expected to be
// topologically sorted.
//
// Use [NewCircuit] to convert from [gkrinfo.Circuit] to this type.
type Circuit []Wire

// NewCircuit converts gkrinfo.Circuit into a concrete Circuit object:
// - The gates are loaded in accordance with their names.
// - It also sets the NbUniqueOutputs fields.
//
// The gateGetter function is used to retrieve gate definitions by name. It is provided for avoiding
// import cycles and should typically be gkrgates.Get.
func NewCircuit(info gkrinfo.Circuit, gateGetter func(name gkr.GateName) *Gate) (Circuit, error) {
	resCircuit := make(Circuit, len(info))
	for i := range info {
		if info[i].Gate == "" && len(info[i].Inputs) == 0 {
			resCircuit[i].Gate = Identity() // input wire
			continue
		}
		resCircuit[i].Inputs = info[i].Inputs
		resCircuit[i].Gate = gateGetter(gkr.GateName(info[i].Gate))
		if resCircuit[i].Gate == nil {
			return nil, fmt.Errorf("gate \"%s\" not found", info[i].Gate)
		}
	}
	resCircuit.setNbUniqueOutputs()
	return resCircuit, nil
}

// Wires is a slice of pointers to Wire. It is used for propagating claim
// information through the circuit.
type Wires []*Wire

// ClaimPropagationInfo returns sets of indices describing the pruning of claim propagation.
// At the end of sumcheck for wire #wireIndex, we end up with sequences "uniqueEvaluations" and "evaluations",
// the former a subsequence of the latter.
// injection are the indices of the unique evaluations in the original evaluation list.
// injectionRightInverse are the indices of the original evaluations in the unique evaluations list.
// There are no guarantees on the non-unique choice of the semi-inverse map.
func (wires Wires) ClaimPropagationInfo(wireIndex int) (injection, injectionLeftInverse []int) {
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

func (c Circuit) maxGateDegree() int {
	res := 1
	for i := range c {
		if !c[i].IsInput() {
			res = max(res, c[i].Gate.Degree())
		}
	}
	return res
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

// OutputsList for each wire, returns the set of indexes of wires it is input to.
// It also sets the NbUniqueOutputs fields, and sets the wire metadata.
func (c Circuit) OutputsList() [][]int {
	idGate := Identity()
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].NbUniqueOutputs = 0
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
			res[in] = append(res[in], i)
			if _, ok := ins[in]; !ok {
				c[in].NbUniqueOutputs++
				ins[in] = struct{}{}
			}
		}
	}
	return res
}

func (c Circuit) setNbUniqueOutputs() {

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
func (c Circuit) Inputs() []int {
	res := make([]int, 0, len(c))
	for i := range c {
		if c[i].IsInput() {
			res = append(res, i)
		}
	}
	return res
}

// MaxGateNbIn returns the maximum number of inputs of any gate in the circuit.
func (c Circuit) MaxGateNbIn() int {
	res := 0
	for i := range c {
		res = max(res, len(c[i].Inputs))
	}
	return res
}

// SolvingInfo is a GKR circuit along with the number of instances to be solved
// and the used hash function for challenge computation. It is used during GKR
// circuit solving and proving.
//
// Use [NewSolvingInfo] to convert from [gkrinfo.StoringInfo] to this type.
type SolvingInfo struct {
	Circuit     Circuit
	NbInstances int
	HashName    string
}

// NewSolvingInfo converts []gkrinfo.StoringInfo into concrete SolvingInfo objects:
// - The gates are loaded in accordance with their names.
// - The instances/assignments are padded into a power of 2, as needed for creating multilinear extensions.
//
// The gateGetter function is used to retrieve gate definitions by name. It is provided for avoiding
// import cycles and should typically be gkrgates.Get.
func NewSolvingInfo(info []*gkrinfo.StoringInfo, gateGetter func(name gkr.GateName) *Gate) ([]SolvingInfo, error) {
	res := make([]SolvingInfo, len(info))
	for i := range info {
		circuit, err := NewCircuit(info[i].Circuit, gateGetter)
		if err != nil {
			return nil, err
		}
		res[i] = SolvingInfo{
			Circuit:     circuit,
			NbInstances: info[i].NbInstances,
			HashName:    info[i].HashName,
		}
	}
	return res, nil
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment []polynomial.MultiLin

func (a WireAssignment) Permute(p gkrinfo.Permutations) {
	utils.Permute(a, p.WiresPermutation)
	for i := range a {
		if a[i] != nil {
			utils.Permute(a[i], p.InstancesPermutation)
		}
	}
}

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

// ProofSize computes how large the proof for a circuit would be. It needs NbUniqueOutputs to be set.
func (c Circuit) ProofSize(logNbInstances int) int {
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

func statusList(c Circuit) []int {
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
func (c Circuit) TopologicalSort() []*Wire {
	var data topSortData
	data.outputs = c.OutputsList()
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

var ErrZeroFunction = errors.New("detected a zero function")

// some sample gates

// Identity gate: x -> x
func Identity() *Gate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return in[0]
	}, 1, 1, 0, gnark.Curves())
}

// Add2 gate: (x, y) -> x + y
func Add2() *Gate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Add(in[0], in[1])
	}, 2, 1, 0, gnark.Curves())
}

// Sub2 gate: (x, y) -> x - y
func Sub2() *Gate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Sub(in[0], in[1])
	}, 2, 1, 0, gnark.Curves())
}

// Neg gate: x -> -x
func Neg() *Gate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Neg(in[0])
	}, 1, 1, 0, gnark.Curves())
}

// Mul2 gate: (x, y) -> x * y
func Mul2() *Gate {
	return NewGate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		return api.Mul(in[0], in[1])
	}, 2, 2, -1, gnark.Curves())
}
