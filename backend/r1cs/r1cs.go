package r1cs

import "github.com/consensys/gnark/backend"

type R1CS interface {
	Solve(assignment backend.Assignments, _a, _b, _c, _wireValues interface{}) error
	Inspect(solution backend.Assignments, showsInputs bool) (interface{}, error)
}
