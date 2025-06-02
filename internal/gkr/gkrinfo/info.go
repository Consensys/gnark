// Package gkrinfo contains serializable information capable of being saved in a SNARK circuit CS object.
package gkrinfo

import (
	"fmt"
	"sort"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
)

type (
	InputDependency struct {
		OutputWire     int
		OutputInstance int
		InputInstance  int
	}

	Wire struct {
		Gate            string
		Inputs          []int
		NbUniqueOutputs int
	}

	Circuit []Wire

	PrintInfo struct {
		Values   []any
		Instance uint32
		IsGkrVar []bool
	}
	StoringInfo struct {
		Circuit     Circuit
		NbInstances int
		HashName    string
		SolveHintID solver.HintID
		ProveHintID solver.HintID
		Prints      []PrintInfo
	}

	Permutations struct {
		SortedInstances      []int
		SortedWires          []int
		InstancesPermutation []int
		WiresPermutation     []int
	}
)

func (w Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w Wire) IsOutput() bool {
	return w.NbUniqueOutputs == 0
}

func (d *StoringInfo) NewInputVariable() int {
	i := len(d.Circuit)
	d.Circuit = append(d.Circuit, Wire{})
	return i
}

// Compile sorts the Circuit wires, their dependencies and the instances
func (d *StoringInfo) Compile(nbInstances int) (Permutations, error) {

	var p Permutations
	d.NbInstances = nbInstances
	// sort the instances to decide the order in which they are to be solved
	instanceDeps := make([][]int, nbInstances)
	for i := range d.Circuit {
		for _, dep := range d.Dependencies[i] {
			instanceDeps[dep.InputInstance] = append(instanceDeps[dep.InputInstance], dep.OutputInstance)
		}
	}

	p.SortedInstances, _ = utils.TopologicalSort(instanceDeps)
	p.InstancesPermutation = utils.InvertPermutation(p.SortedInstances)

	// this whole circuit sorting is a bit of a charade. if things are built using an api, there's no way it could NOT already be topologically sorted
	// worth keeping for future-proofing?

	inputs := utils.Map(d.Circuit, func(w Wire) []int {
		return w.Inputs
	})

	var uniqueOuts [][]int
	p.SortedWires, uniqueOuts = utils.TopologicalSort(inputs)
	p.WiresPermutation = utils.InvertPermutation(p.SortedWires)
	wirePermutationAt := utils.SliceAt(p.WiresPermutation)
	sorted := make([]Wire, len(d.Circuit)) // TODO: Directly manipulate d.circuit instead
	sortedDeps := make([][]InputDependency, len(d.Circuit))

	// go through the wires in the sorted order and fix the input and dependency indices according to the permutations
	for newI, oldI := range p.SortedWires {
		oldW := d.Circuit[oldI]

		for depI := range d.Dependencies[oldI] {
			dep := &d.Dependencies[oldI][depI]
			dep.OutputWire = p.WiresPermutation[dep.OutputWire]
			dep.InputInstance = p.InstancesPermutation[dep.InputInstance]
			dep.OutputInstance = p.InstancesPermutation[dep.OutputInstance]
		}
		sort.Slice(d.Dependencies[oldI], func(i, j int) bool {
			return d.Dependencies[oldI][i].InputInstance < d.Dependencies[oldI][j].InputInstance
		})
		for i := 1; i < len(d.Dependencies[oldI]); i++ {
			if d.Dependencies[oldI][i].InputInstance == d.Dependencies[oldI][i-1].InputInstance {
				return p, fmt.Errorf("an input wire can only have one dependency per instance")
			}
		} // TODO: Check that dependencies and explicit assignments cover all instances

		sortedDeps[newI] = d.Dependencies[oldI]
		sorted[newI] = Wire{
			Gate:            oldW.Gate,
			Inputs:          utils.Map(oldW.Inputs, wirePermutationAt),
			NbUniqueOutputs: len(uniqueOuts[oldI]),
		}
	}

	// re-arrange the prints
	for i := range d.Prints {
		for j, isVar := range d.Prints[i].IsGkrVar {
			if isVar {
				d.Prints[i].Values[j] = uint32(p.WiresPermutation[d.Prints[i].Values[j].(uint32)])
			}
		}
	}

	d.Circuit, d.Dependencies = sorted, sortedDeps

	return p, nil
}

func (d *StoringInfo) Is() bool {
	return d.Circuit != nil
}

// A ConstraintSystem that supports GKR
type ConstraintSystem interface {
	SetGkrInfo(info StoringInfo) error
}

// NewPrintInfoMap partitions printInfo into map elements, indexed by instance
func NewPrintInfoMap(printInfo []PrintInfo) map[uint32][]PrintInfo {
	res := make(map[uint32][]PrintInfo)
	for i := range printInfo {
		res[printInfo[i].Instance] = append(res[printInfo[i].Instance], printInfo[i])
	}
	return res
}
