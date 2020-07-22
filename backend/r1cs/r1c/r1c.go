package r1c

// LinearExpression represent a linear expression of variables
type LinearExpression []Term

// R1C used to compute the wires
type R1C struct {
	L      LinearExpression
	R      LinearExpression
	O      LinearExpression
	Solver SolvingMethod
}

// SolvingMethod is used by the R1CS solver
// note: it is not in backend/r1cs to avoid an import cycle
type SolvingMethod uint8

// SingleOuput and BinaryDec are types of solving method for rank-1 constraints
const (
	SingleOutput SolvingMethod = iota
	BinaryDec
)
