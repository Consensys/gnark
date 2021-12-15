package cs

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// system represents a constraint system that can be loaded using the bootloader
type System interface {
	frontend.API
	NewPublicVariable(name string) frontend.Variable
	NewSecretVariable(name string) frontend.Variable
	Compile(curveID ecc.ID) (compiled.ConstraintSystem, error)
}

type NewSystem func(ecc.ID) (System, error)

// buildCS builds the constraint system. It bootstraps the inputs
// allocations by parsing the circuit's underlying structure, then
// it builds the constraint system using the Define method.
func NewCompiler(maker NewSystem) frontend.Compiler {
	return func(curve ecc.ID, circuit frontend.Circuit) (ccs compiled.ConstraintSystem, err error) {
		system, err := maker(curve)
		if err != nil {
			return nil, fmt.Errorf("new system: %w", err)
		}
		// leaf handlers are called when encoutering leafs in the circuit data struct
		// leafs are Constraints that need to be initialized in the context of compiling a circuit
		var handler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
			if tInput.CanSet() {
				switch visibility {
				case compiled.Secret:
					tInput.Set(reflect.ValueOf(system.NewSecretVariable(name)))
				case compiled.Public:
					tInput.Set(reflect.ValueOf(system.NewPublicVariable(name)))
				case compiled.Unset:
					return errors.New("can't set val " + name + " visibility is unset")
				}

				return nil
			}
			return errors.New("can't set val " + name)
		}
		// recursively parse through reflection the circuits members to find all Constraints that need to be allocated
		// (secret or public inputs)
		if err := parser.Visit(circuit, "", compiled.Unset, handler, tVariable); err != nil {
			return nil, err
		}

		// recover from panics to print user-friendlier messages
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v\n%s", r, debug.Stack())
			}
		}()

		// call Define() to fill in the Constraints
		if err = circuit.Define(system); err != nil {
			return nil, fmt.Errorf("define circuit: %w", err)
		}

		ccs, err = system.Compile()
		if err != nil {
			return nil, fmt.Errorf("compile system: %w", err)
		}

		return
	}
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
