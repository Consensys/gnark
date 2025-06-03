// Package gkrinfo contains serializable information capable of being saved in a SNARK circuit CS object.
package gkrinfo

import (
	"github.com/consensys/gnark/constraint/solver"
)

type (
	InputDependency struct {
		OutputWire     int
		OutputInstance int
		InputInstance  int
	}

	Wire struct {
		Gate   string
		Inputs []int
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

func (d *StoringInfo) NewInputVariable() int {
	i := len(d.Circuit)
	d.Circuit = append(d.Circuit, Wire{})
	return i
}

func (d *StoringInfo) Is() bool {
	return d.Circuit != nil
}

// A ConstraintSystem that supports GKR
type ConstraintSystem interface {
	SetGkrInfo(info StoringInfo) error
}
