package gkr_info

type Wire[T any] struct {
	Gate            T
	Inputs          []int
	Dependencies    []InputDependency // nil for input wires
	NbUniqueOutputs int
}

func (w Wire[T]) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w Wire[T]) IsOutput() bool {
	return w.NbUniqueOutputs == 0
}

func (w Wire[T]) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.NbUniqueOutputs
}

func (w Wire[T]) NoProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

func (w Wire[T]) NbUniqueInputs() int {
	set := make(map[int]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

type (
	Circuit[T any] []Wire[T]
	CircuitInfo    Circuit[string]
)

// Chunks returns intervals of instances that are independent of each other and can be solved in parallel
func (c CircuitInfo) Chunks(nbInstances int) []int {
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
