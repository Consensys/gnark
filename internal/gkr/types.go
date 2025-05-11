package gkr

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrgate"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/std/polynomial"
)

type Wire struct {
	Gate            *gkrgate.Gate
	Inputs          []int
	NbUniqueOutputs int
}

func (w Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w Wire) IsOutput() bool {
	return w.NbUniqueOutputs == 0
}

func (w Wire) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.NbUniqueOutputs
}

func (w Wire) NoProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

func (w Wire) NbUniqueInputs() int {
	set := make(map[int]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

type (
	Circuit []Wire
	Wires   []*Wire
)

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

	proofI := 0
	for inI, in := range w.Inputs {
		if indexInProof[in] == -1 { // not found
			injection[proofI] = inI
			indexInProof[in] = proofI
			proofI++
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

type SolvingInfo struct {
	Circuit      Circuit
	Dependencies [][]gkrinfo.InputDependency
	MaxNIns      int
	NbInstances  int
	HashName     string
}

// Chunks returns intervals of instances that are independent of each other and can be solved in parallel
func (info *SolvingInfo) Chunks() []int {
	res := make([]int, 0, 1)
	lastSeenDependencyI := make([]int, len(info.Circuit))

	for start, end := 0, 0; start != info.NbInstances; start = end {
		end = info.NbInstances
		endWireI := -1
		for wI := range info.Circuit {
			deps := info.Dependencies[wI]
			if wDepI := lastSeenDependencyI[wI]; wDepI < len(deps) && deps[wDepI].InputInstance < end {
				end = deps[wDepI].InputInstance
				endWireI = wI
			}
		}
		if endWireI != -1 {
			lastSeenDependencyI[endWireI]++
		}
		res = append(res, end)
	}
	return res
}

// AssignmentOffsets returns the index of the first value assigned to a wire TODO: Explain clearly
func (info *SolvingInfo) AssignmentOffsets() []int {
	c := info.Circuit
	res := make([]int, len(c)+1)
	for i := range c {
		nbExplicitAssignments := 0
		if c[i].IsInput() {
			nbExplicitAssignments = info.NbInstances - len(info.Dependencies[i])
		}
		res[i+1] = res[i] + nbExplicitAssignments
	}
	return res
}

// OutputsList for each wire, returns the set of indexes of wires it is input to.
// It also sets the NbUniqueOutputs fields, and sets the wire metadata.
func (c Circuit) OutputsList() [][]int {
	idGate := gkrgate.New(
		func(_ gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
			return x[0]
		},
		1,
		1,
		1,
	)
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

func CircuitInfoToCircuit(info gkrinfo.Circuit, gateGetter func(name gkr.GateName) *gkrgate.Gate) Circuit {
	resCircuit := make(Circuit, len(info))
	for i := range info {
		resCircuit[i].Inputs = info[i].Inputs
		resCircuit[i].Gate = gateGetter(gkr.GateName(info[i].Gate))
	}
	return resCircuit
}

func StoringToSolvingInfo(info gkrinfo.StoringInfo, gateGetter func(name gkr.GateName) *gkrgate.Gate) SolvingInfo {
	return SolvingInfo{
		Circuit:     CircuitInfoToCircuit(info.Circuit, gateGetter),
		MaxNIns:     info.MaxNIns,
		NbInstances: info.NbInstances,
		HashName:    info.HashName,
	}
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
