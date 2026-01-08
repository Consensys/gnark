// Package gkrinfo contains serializable information capable of being saved in a SNARK circuit CS object.
package gkrinfo

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

	StoringInfo struct {
		Circuit     Circuit
		NbInstances int
		HashName    string
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

// A ConstraintSystem that supports GKR. If a constraint system implements this
// interface, then it stores and proves GKR sub-circuits automatically at circuit
// solving time.
type ConstraintSystem interface {
	// NewGkr registers a GKR sub-circuit, returning a reference to an object
	// where serializable data about the sub-circuit is to be stored, and an
	// index as a reference to the GKR sub-circuit. The index is the first
	// argument to all GKR-related hints.
	NewGkr() (*StoringInfo, int)
}
