package frontend

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend/schema"
)

type NewBuilder func(ecc.ID, CompileConfig) (Builder, error)

// Compiler represents a constraint system compiler
type Compiler interface {
	// MarkBoolean sets (but do not constraint!) v to be boolean
	// This is useful in scenarios where a variable is known to be boolean through a constraint
	// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
	MarkBoolean(v Variable)

	// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
	// Use with care; variable may not have been **constrained** to be boolean
	// This returns true if the v is a constant and v == 0 || v == 1.
	IsBoolean(v Variable) bool

	// NewHint initializes internal variables whose value will be evaluated
	// using the provided hint function at run time from the inputs. Inputs must
	// be either variables or convertible to *big.Int. The function returns an
	// error if the number of inputs is not compatible with f.
	//
	// The hint function is provided at the proof creation time and is not
	// embedded into the circuit. From the backend point of view, the variable
	// returned by the hint function is equivalent to the user-supplied witness,
	// but its actual value is assigned by the solver, not the caller.
	//
	// No new constraints are added to the newly created wire and must be added
	// manually in the circuit. Failing to do so leads to solver failure.
	//
	// If nbOutputs is specified, it must be >= 1 and <= f.NbOutputs
	NewHint(f hint.Function, nbOutputs int, inputs ...Variable) ([]Variable, error)

	// Tag creates a tag at a given place in a circuit. The state of the tag may contain informations needed to
	// measure constraints, variables and coefficients creations through AddCounter
	Tag(name string) Tag

	// AddCounter measures the number of constraints, variables and coefficients created between two tags
	// note that the PlonK statistics are contextual since there is a post-compile phase where linear expressions
	// are factorized. That is, measuring 2 times the "repeating" piece of circuit may give less constraints the second time
	AddCounter(from, to Tag)

	// ConstantValue returns the big.Int value of v and true if op is a success.
	// nil and false if failure. This API returns a boolean to allow for future refactoring
	// replacing *big.Int with fr.Element
	ConstantValue(v Variable) (*big.Int, bool)

	// CurveID returns the ecc.ID injected by the compiler
	Curve() ecc.ID

	// Backend returns the backend.ID injected by the compiler
	Backend() backend.ID
}

// Builder represents a constraint system builder
type Builder interface {
	API
	Compiler

	// Compile is called after circuit.Define() to produce a final IR (CompiledConstraintSystem)
	Compile() (CompiledConstraintSystem, error)

	// SetSchema is used internally by frontend.Compile to set the circuit schema
	SetSchema(*schema.Schema)

	// AddPublicVariable is called by the compiler when parsing the circuit schema. It panics if
	// called inside circuit.Define()
	AddPublicVariable(name string) Variable

	// AddSecretVariable is called by the compiler when parsing the circuit schema. It panics if
	// called inside circuit.Define()
	AddSecretVariable(name string) Variable
}
