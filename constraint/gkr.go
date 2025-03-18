package constraint

import (
	"fmt"
	"sort"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
)

type GkrVariable int // Just an alias to hide implementation details. May be more trouble than worth

type InputDependency struct {
	OutputWire     int
	OutputInstance int
	InputInstance  int
}

type GkrWire struct {
	Gate            string // TODO: Change to description
	Inputs          []int
	Dependencies    []InputDependency // nil for input wires
	NbUniqueOutputs int
}

type GkrCircuit []GkrWire

type GkrInfo struct {
	Circuit     GkrCircuit
	MaxNIns     int
	NbInstances int
	HashName    string
	SolveHintID solver.HintID
	ProveHintID solver.HintID
}

type GkrPermutations struct {
	SortedInstances      []int
	SortedWires          []int
	InstancesPermutation []int
	WiresPermutation     []int
}

func (w GkrWire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w GkrWire) IsOutput() bool {
	return w.NbUniqueOutputs == 0
}

// AssignmentOffsets calculates and returns an array where each element represents
// the index of the first value assigned to a specific wire in the circuit.
//
// - `res[i]`: Represents the **starting index** of values assigned to wire `i`.
// - `res[i+1]`: Represents the **starting index** of values assigned to the next wire (`i+1`).
// - If a wire is an **independent input**, its assigned values are determined directly.
//   However, if it **depends on other wires**, the number of assignments is adjusted
//   based on the dependencies (`nbExplicitAssignments` calculation).
//
//  This function ensures that each wire in the `Circuit` has a correctly assigned
//    starting index for its values, helping track assignments efficiently.

func (d *GkrInfo) AssignmentOffsets() []int {
	c := d.Circuit
	res := make([]int, len(c)+1) // One extra element for easier boundary calculations.
	for i := range c {
		nbExplicitAssignments := 0
		// If the wire is an independent input
		if c[i].IsInput() {
			// Determine the number of non-dependent instances
			nbExplicitAssignments = d.NbInstances - len(c[i].Dependencies)
		}
		// Compute the offset by adding to the previous index
		res[i+1] = res[i] + nbExplicitAssignments
	}
	return res
}

func (d *GkrInfo) NewInputVariable() GkrVariable {
	i := len(d.Circuit)
	d.Circuit = append(d.Circuit, GkrWire{})
	return GkrVariable(i)
}

// Compile sorts the circuit wires, their dependencies and the instances
func (d *GkrInfo) Compile(nbInstances int) (GkrPermutations, error) {

	var p GkrPermutations
	d.NbInstances = nbInstances
	// sort the instances to decide the order in which they are to be solved
	instanceDeps := make([][]int, nbInstances)
	for i := range d.Circuit {
		for _, dep := range d.Circuit[i].Dependencies {
			instanceDeps[dep.InputInstance] = append(instanceDeps[dep.InputInstance], dep.OutputInstance)
		}
	}

	p.SortedInstances, _ = utils.TopologicalSort(instanceDeps)
	p.InstancesPermutation = utils.InvertPermutation(p.SortedInstances)

	// this whole circuit sorting is a bit of a charade. if things are built using an api, there's no way it could NOT already be topologically sorted
	// worth keeping for future-proofing?

	inputs := utils.Map(d.Circuit, func(w GkrWire) []int {
		return w.Inputs
	})

	var uniqueOuts [][]int
	p.SortedWires, uniqueOuts = utils.TopologicalSort(inputs)
	p.WiresPermutation = utils.InvertPermutation(p.SortedWires)
	wirePermutationAt := utils.SliceAt(p.WiresPermutation)
	sorted := make([]GkrWire, len(d.Circuit)) // TODO: Directly manipulate d.Circuit instead
	for newI, oldI := range p.SortedWires {
		oldW := d.Circuit[oldI]

		if !oldW.IsInput() {
			d.MaxNIns = max(d.MaxNIns, len(oldW.Inputs))
		}

		for j := range oldW.Dependencies {
			dep := &oldW.Dependencies[j]
			dep.OutputWire = p.WiresPermutation[dep.OutputWire]
			dep.InputInstance = p.InstancesPermutation[dep.InputInstance]
			dep.OutputInstance = p.InstancesPermutation[dep.OutputInstance]
		}
		sort.Slice(oldW.Dependencies, func(i, j int) bool {
			return oldW.Dependencies[i].InputInstance < oldW.Dependencies[j].InputInstance
		})
		for i := 1; i < len(oldW.Dependencies); i++ {
			if oldW.Dependencies[i].InputInstance == oldW.Dependencies[i-1].InputInstance {
				return p, fmt.Errorf("an input wire can only have one dependency per instance")
			}
		} // TODO: Check that dependencies and explicit assignments cover all instances

		sorted[newI] = GkrWire{
			Gate:            oldW.Gate,
			Inputs:          utils.Map(oldW.Inputs, wirePermutationAt),
			Dependencies:    oldW.Dependencies,
			NbUniqueOutputs: len(uniqueOuts[oldI]),
		}
	}
	d.Circuit = sorted

	return p, nil
}

func (d *GkrInfo) Is() bool {
	return d.Circuit != nil
}

// Chunks returns intervals of instances that are independent of each other and can be solved in parallel
func (c GkrCircuit) Chunks(nbInstances int) []int {
	res := make([]int, 0, 1)
	lastSeenDependencyI := make([]int, len(c))

	for start, end := 0, 0; start != nbInstances; start = end {
		end = nbInstances
		endWireI := -1
		for wI, w := range c {
			if wDepI := lastSeenDependencyI[wI]; wDepI < len(w.Dependencies) && w.Dependencies[wDepI].InputInstance < end {
				end = w.Dependencies[wDepI].InputInstance
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
