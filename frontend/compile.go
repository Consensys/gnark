package frontend

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
)

type Builder interface {
	API
	Compiler

	// Compile is called after circuit.Define() to produce a final IR (CompiledConstraintSystem)
	Compile(opt CompileConfig) (CompiledConstraintSystem, error)

	// SetSchema is used internally by frontend.Compile to set the circuit schema
	SetSchema(*schema.Schema)

	// AddPublicVariable is called by the compiler when parsing the circuit schema. It panics if
	// called inside circuit.Define()
	AddPublicVariable(name string) Variable

	// AddSecretVariable is called by the compiler when parsing the circuit schema. It panics if
	// called inside circuit.Define()
	AddSecretVariable(name string) Variable
}

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

type NewCompiler func(ecc.ID) (Builder, error)

// Compile will generate a ConstraintSystem from the given circuit
//
// 1. it will first allocate the user inputs (see type Tag for more info)
// example:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"exponent,public"`
// 		}
// in that case, Compile() will allocate one public variable with id "exponent"
//
// 2. it then calls circuit.Define(curveID, R1CS) to build the internal constraint system
// from the declarative code
//
// 3. finally, it converts that to a ConstraintSystem.
// 		if zkpID == backend.GROTH16	→ R1CS
//		if zkpID == backend.PLONK 	→ SparseR1CS
//
// initialCapacity is an optional parameter that reserves memory in slices
// it should be set to the estimated number of constraints in the circuit, if known.
func Compile(curveID ecc.ID, newCompiler NewCompiler, circuit Circuit, opts ...CompileOption) (CompiledConstraintSystem, error) {
	// parse options
	opt := CompileConfig{}
	for _, o := range opts {
		if err := o(&opt); err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}

	// instantiate new compiler
	compiler, err := newCompiler(curveID)
	if err != nil {
		return nil, fmt.Errorf("new compiler: %w", err)
	}

	// parse the circuit builds a schema of the circuit
	// and call circuit.Define() method to initialize a list of constraints in the compiler
	if err = parseCircuit(compiler, circuit); err != nil {
		return nil, fmt.Errorf("parse circuit: %w", err)

	}

	// compile the circuit into its final form
	return compiler.Compile(opt)
}

func parseCircuit(builder Builder, circuit Circuit) (err error) {
	// ensure circuit.Define has pointer receiver
	if reflect.ValueOf(circuit).Kind() != reflect.Ptr {
		return errors.New("frontend.Circuit methods must be defined on pointer receiver")
	}

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	var handler schema.LeafHandler = func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		if tInput.CanSet() {
			switch visibility {
			case schema.Secret:
				tInput.Set(reflect.ValueOf(builder.AddSecretVariable(name)))
			case schema.Public:
				tInput.Set(reflect.ValueOf(builder.AddPublicVariable(name)))
			case schema.Unset:
				return errors.New("can't set val " + name + " visibility is unset")
			}

			return nil
		}
		return errors.New("can't set val " + name)
	}
	// recursively parse through reflection the circuits members to find all Constraints that need to be allocated
	// (secret or public inputs)
	s, err := schema.Parse(circuit, tVariable, handler)
	if err != nil {
		return err
	}
	builder.SetSchema(s)

	// recover from panics to print user-friendlier messages
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v\n%s", r, debug.Stack())
		}
	}()

	// call Define() to fill in the Constraints
	if err = circuit.Define(builder); err != nil {
		return fmt.Errorf("define circuit: %w", err)
	}

	return
}

// CompileOption defines option for altering the behaviour of the Compile
// method. See the descriptions of the functions returning instances of this
// type for available options.
type CompileOption func(opt *CompileConfig) error

type CompileConfig struct {
	Capacity                  int
	IgnoreUnconstrainedInputs bool
}

// WithCapacity is a compile option that specifies the estimated capacity needed
// for internal variables and constraints. If not set, then the initial capacity
// is 0 and is dynamically allocated as needed.
func WithCapacity(capacity int) CompileOption {
	return func(opt *CompileConfig) error {
		opt.Capacity = capacity
		return nil
	}
}

// IgnoreUnconstrainedInputs is a compile option which allow compiling input
// circuits where not all inputs are not constrained. If not set, then the
// compiler returns an error if there exists an unconstrained input.
//
// This option is useful for debugging circuits, but should not be used in
// production settings as it means that there is a potential error in the
// circuit definition or that it is possible to optimize witness size.
func IgnoreUnconstrainedInputs() CompileOption {
	return func(opt *CompileConfig) error {
		opt.IgnoreUnconstrainedInputs = true
		return nil
	}
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A Variable }{}).FieldByName("A").Type()
}
