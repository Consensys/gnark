package constraint

import (
	"github.com/consensys/gnark/constraint/solver"
)

// HintMapping mark a list of output variables to be computed using provided hint and inputs.
type HintMapping struct {
	HintID  solver.HintID      // Hint function id
	Inputs  []LinearExpression // Terms to inject in the hint function
	Outputs []int              // IDs of wires the hint outputs map to
}

// WireIterator implements constraint.Iterable
func (h *HintMapping) WireIterator() func() int {
	curr := 0
	n := 0
	for i := 0; i < len(h.Inputs); i++ {
		n += len(h.Inputs[i])
	}
	inputs := make([]int, 0, n)
	for i := 0; i < len(h.Inputs); i++ {
		for j := 0; j < len(h.Inputs[i]); j++ {
			term := h.Inputs[i][j]
			if term.IsConstant() {
				continue
			}
			inputs = append(inputs, int(term.VID))
		}
	}

	return func() int {
		if curr < len(h.Outputs) {
			curr++
			return h.Outputs[curr-1]
		}
		if curr < len(h.Outputs)+len(inputs) {
			curr++
			return inputs[curr-1-len(h.Outputs)]
		}
		return -1
	}
}
