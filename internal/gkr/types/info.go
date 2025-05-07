// Package types contains common types used in the GKR protocol, that don't need to be exposed to the end user.
package types

import (
	"fmt"
	"sort"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
)

type InputDependency struct {
	OutputWire     int
	OutputInstance int
	InputInstance  int
}

type GkrInfo struct {
	Circuit     CircuitInfo
	MaxNIns     int
	NbInstances int
	HashName    string
	SolveHintID solver.HintID
	ProveHintID solver.HintID
}

type Permutations struct {
	SortedInstances      []int
	SortedWires          []int
	InstancesPermutation []int
	WiresPermutation     []int
}

// AssignmentOffsets returns the index of the first value assigned to a wire TODO: Explain clearly
func (d *GkrInfo) AssignmentOffsets() []int {
	c := d.Circuit
	res := make([]int, len(c)+1)
	for i := range c {
		nbExplicitAssignments := 0
		if c[i].IsInput() {
			nbExplicitAssignments = d.NbInstances - len(c[i].Dependencies)
		}
		res[i+1] = res[i] + nbExplicitAssignments
	}
	return res
}

func (d *GkrInfo) NewInputVariable() int {
	i := len(d.Circuit)
	d.Circuit = append(d.Circuit, Wire[string]{})
	return i
}

// Compile sorts the circuit wires, their dependencies and the instances
func (d *GkrInfo) Compile(nbInstances int) (Permutations, error) {

	var p Permutations
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

	inputs := utils.Map(d.Circuit, func(w Wire[string]) []int {
		return w.Inputs
	})

	var uniqueOuts [][]int
	p.SortedWires, uniqueOuts = utils.TopologicalSort(inputs)
	p.WiresPermutation = utils.InvertPermutation(p.SortedWires)
	wirePermutationAt := utils.SliceAt(p.WiresPermutation)
	sorted := make([]Wire[string], len(d.Circuit)) // TODO: Directly manipulate d.Circuit instead
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

		sorted[newI] = Wire[string]{
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

// A ConstraintSystem that supports GKR
type ConstraintSystem interface {
	SetGkrInfo(info GkrInfo) error
}
