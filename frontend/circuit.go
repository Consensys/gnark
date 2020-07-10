package frontend

import (
	"errors"
	"reflect"

	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/encoding/gob"
)

// Circuit must be implemented by user-defined circuits
type Circuit interface {
	// Define declares the circuit's constraints
	Define(ctx *Context, cs *CS) error

	// PostInit is called by frontend.Compile() after the automatic initialization of CircuitVariable
	// In some cases, we may have custom allocations to do (foreign keys, alias in constraints, ...)
	PostInit(ctx *Context) error
}

// Compile will parse provided circuit struct members and initialize all leafs that
// are CircuitVariable with frontend.constraint objects
// Struct tag options are similar to encoding/json
// For example:
// type myCircuit struct {
//  A frontend.Variable `gnark:"inputName"` 	// will allocate a secret (default visibility) input with name inputName
//  B frontend.Variable `gnark:",public"` 	// will allocate a public input name with "B" (struct member name)
//  C frontend.Variable `gnark:"-"` 			// C will not be initialized, and has to be initialized in circuit.PostInit hook
// }
func Compile(ctx *Context, circuit Circuit) (r1cs.R1CS, error) {
	// instantiate our constraint system
	cs := New()

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are constraints that need to be initialized in the context of compiling a circuit
	var handler leafHandler = func(visibility attrVisibility, name string, tInput reflect.Value) error {
		if tInput.CanSet() {
			v := tInput.Interface().(Variable)
			if v.constraint != nil {
				return errors.New("circuit was already compiled")
			}
			if v.val != nil {
				return errors.New("circuit has some assigned values, can't compile")
			}
			switch visibility {
			case unset, secret:
				tInput.Set(reflect.ValueOf(cs.SECRET_INPUT(name)))
			case public:
				tInput.Set(reflect.ValueOf(cs.PUBLIC_INPUT(name)))
			}

			return nil
		}
		return errors.New("can't set val " + name)
	}

	// recursively parse through reflection the circuits members to find all constraints that need to be allocated
	// (secret or public inputs)
	if err := parseType(circuit, "", unset, handler); err != nil {
		return nil, err
	}

	// allow user circuit to perform custom allocations / init clean up.
	if err := circuit.PostInit(ctx); err != nil {
		return nil, err
	}

	// TODO maybe lock input variables allocations to forbid user to call circuit.SECRET_INPUT() inside the Circuit() method

	// call Define() to fill in the constraints
	if err := circuit.Define(ctx, &cs); err != nil {
		return nil, err
	}

	// return R1CS

	// we have in our context object the curve, so we can type our R1CS to the curve base field elements
	return cs.ToR1CS().ToR1CS(ctx.CurveID()), nil
}

// Save will serialize the provided R1CS to path
func Save(ctx *Context, r1cs r1cs.R1CS, path string) error {
	return gob.Write(path, r1cs, ctx.CurveID())
}

// ToAssignment will parse provided circuit and extract all values from leaves that are
// CircuitVariable.
// if MakeAssignable was not call prior, will panic.
// TODO note, this is likely going to dissapear in a future refactoring. This method exist to provide compatibility with map[string]interface{}
func ToAssignment(circuit Circuit) (map[string]interface{}, error) {
	toReturn := make(map[string]interface{})
	var extractHandler leafHandler = func(visibility attrVisibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(Variable)
		if v.val == nil {
			return errors.New(name + " has no assigned value.")
		}
		toReturn[name] = v.val
		return nil
	}
	// recursively parse through reflection the circuits members to find all inputs that need to be allocated
	// (secret or public inputs)
	return toReturn, parseType(circuit, "", unset, extractHandler)
}
