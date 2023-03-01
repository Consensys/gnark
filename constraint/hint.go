package constraint

import "github.com/consensys/gnark/constraint/solver"

// Hint represents a solver hint
// it enables the solver to compute a Wire with a function provided at solving time
// using pre-defined inputs
type Hint struct {
	ID     solver.HintID      // hint function id
	Inputs []LinearExpression // terms to inject in the hint function
	Wires  []int              // IDs of wires the hint outputs map to
}
