package constraint

import (
	"io"
	"math/big"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
)

// ConstraintSystem interface that all constraint systems implement.
type ConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom
	Field
	Resolver

	// IsSolved returns nil if given witness solves the constraint system and error otherwise
	// Deprecated: use _, err := Solve(...) instead
	IsSolved(witness witness.Witness, opts ...solver.Option) error

	// Solve attempts to solves the constraint system using provided witness.
	// Returns an error if the witness does not allow all the constraints to be satisfied.
	// Returns a typed solution (R1CSSolution or SparseR1CSSolution) and nil otherwise.
	Solve(witness witness.Witness, opts ...solver.Option) (any, error)

	// GetNbVariables return number of internal, secret and public Variables
	// Deprecated: use GetNbSecretVariables() instead
	GetNbVariables() (internal, secret, public int)

	GetNbInternalVariables() int
	GetNbSecretVariables() int
	GetNbPublicVariables() int

	GetNbInstructions() int
	GetNbConstraints() int
	GetNbCoefficients() int

	Field() *big.Int
	FieldBitLen() int

	AddPublicVariable(name string) int
	AddSecretVariable(name string) int
	AddInternalVariable() int

	// AddSolverHint adds a hint to the solver such that the output variables will be computed
	// using a call to output := f(input...) at solve time.
	AddSolverHint(f solver.Hint, input []LinearExpression, nbOutput int) (internalVariables []int, err error)

	AddCommitment(c Commitment) error

	AddLog(l LogEntry)

	// MakeTerm returns a new Term. The constraint system may store coefficients in a map, so
	// calls to this function will grow the memory usage of the constraint system.
	MakeTerm(coeff *Element, variableID int) Term

	// AddCoeff adds a coefficient to the underlying constraint system. The system will not store duplicate,
	// but is not purging for unused coeff either, so this grows memory usage.
	AddCoeff(coeff Element) uint32

	NewDebugInfo(errName string, i ...interface{}) DebugInfo

	// AttachDebugInfo enables attaching debug information to multiple constraints.
	// This is more efficient than using the AddR1C(.., debugInfo) since it will store the
	// debug information only once.
	AttachDebugInfo(debugInfo DebugInfo, constraintID []int)

	// CheckUnconstrainedWires returns and error if the constraint system has wires that are not uniquely constrained.
	// This is experimental.
	CheckUnconstrainedWires() error

	// AddBlueprint registers the given blueprint and returns its id. This should be called only once per blueprint.
	AddBlueprint(b Blueprint) BlueprintID

	GetInstruction(int) Instruction

	GetCoefficient(i int) Element

	// GetCallData re-slice the constraint system full calldata slice with the portion
	// related to the instruction. This does not copy and caller should not modify.
	GetCallData(instruction Instruction) []uint32
}

type Iterable interface {
	// WireIterator returns a new iterator to iterate over the wires of the implementer (usually, a constraint)
	// Call to next() returns the next wireID of the Iterable object and -1 when iteration is over.
	//
	// For example a R1C constraint with L, R, O linear expressions, each of size 2, calling several times
	// 		next := r1c.WireIterator();
	// 		for wID := next(); wID != -1; wID = next() {}
	//		// will return in order L[0],L[1],R[0],R[1],O[0],O[1],-1
	WireIterator() (next func() int)
}

var _ Iterable = &SparseR1C{}
var _ Iterable = &R1C{}
