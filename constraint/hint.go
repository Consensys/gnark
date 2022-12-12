package constraint

import (
	"github.com/consensys/gnark/backend/hint"
)

// Hint represents a solver hint
// it enables the solver to compute a Wire with a function provided at solving time
// using pre-defined inputs
type Hint struct {
	ID     hint.ID            // hint function id
	Inputs []LinearExpression // terms to inject in the hint function
	Wires  []int              // IDs of wires the hint outputs map to
}
