package constraint

// Solver represents the state of a constraint system solver at runtime. Blueprint can interact
// with this object to perform run time logic, solve constraints and assign values in the solution.
type Solver interface {
	Field
	GetValue(cID, vID uint32) Element
	GetCoeff(cID uint32) Element
	SetValue(vID uint32, f Element)
}
