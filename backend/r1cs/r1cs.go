package r1cs

type R1CS interface {
	Solve(assignment map[string]interface{}, _a, _b, _c, _wireValues interface{}) error
	Inspect(solution map[string]interface{}, showsInputs bool) (map[string]interface{}, error)
	GetNbConstraints() int // TODO rename to NbConstraints
}
