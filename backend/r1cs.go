package backend

type R1CS interface {
	Solve(assignment Assignments, _a, _b, _c, _wireValues interface{}) error
	Inspect(solution Assignments, showsInputs bool) (interface{}, error)
}
