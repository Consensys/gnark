package types

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
