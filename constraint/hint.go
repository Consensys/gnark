package constraint

import (
	"github.com/consensys/gnark/constraint/solver"
)

type HintIds struct {
	UUID solver.HintID
	Name string
}

type HintIdOption func(*HintIds)

func WithHintId(id solver.HintID) HintIdOption {
	return func(_id *HintIds) {
		_id.UUID = id
	}
}

func WithHintName(name string) HintIdOption {
	return func(id *HintIds) {
		id.Name = name
	}
}

// HintMapping mark a list of output variables to be computed using provided hint and inputs.
type HintMapping struct {
	HintID      solver.HintID      // Hint function id
	Inputs      []LinearExpression // Terms to inject in the hint function
	OutputRange struct {           // IDs of wires the hint outputs map to
		Start, End uint32
	}
}
