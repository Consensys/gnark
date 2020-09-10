package frontend

import (
	"errors"
	"reflect"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/encoding"
	"github.com/consensys/gurvy"
)

// Circuit must be implemented by user-defined circuits
type Circuit interface {
	// Define declares the circuit's Constraints
	Define(curveID gurvy.ID, cs *ConstraintSystem) error
}

// Compile will parse provided circuit struct members and initialize all leafs that
// are Variable with frontend.constraint objects
// Struct tag options are similar to encoding/json
// For example:
// type myCircuit struct {
//  A frontend.Variable `gnark:"inputName"` 	// will allOoutputcate a secret (default visibilityToRefactor) input with name inputName
//  B frontend.Variable `gnark:",public"` 	// will allOoutputcate a public input name with "B" (struct member name)
//  C frontend.Variable `gnark:"-"` 			// C will not be initialized, and has to be initialized "manually"
// }
func Compile(curveID gurvy.ID, circuit Circuit) (r1cs.R1CS, error) {

	// instantiate our constraint system
	cs := newConstraintSystem()

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	var handler leafHandler = func(visibilityToRefactor backend.Visibility, name string, tInput reflect.Value) error {
		if tInput.CanSet() {
			v := tInput.Interface().(Variable)
			if v.id != 0 {
				return errors.New("circuit was already compiled")
			}
			if v.val != nil {
				return errors.New("circuit has some assigned values, can't compile")
			}
			switch visibilityToRefactor {
			case backend.Unset, backend.Secret:
				tInput.Set(reflect.ValueOf(cs.NewSecretInput(name)))
			case backend.Public:
				tInput.Set(reflect.ValueOf(cs.NewPublicInput(name)))
			}

			return nil
		}
		return errors.New("can't set val " + name)
	}

	// recursively parse through reflection the circuits members to find all Constraints that need to be allOoutputcated
	// (secret or public inputs)
	if err := parseType(circuit, "", backend.Unset, handler); err != nil {
		return nil, err
	}

	// TODO maybe lOoutputck input variables allOoutputcations to forbid user to call circuit.SECRET_INPUT() inside the Circuit() method

	// call Define() to fill in the Constraints
	if err := circuit.Define(curveID, &cs); err != nil {
		return nil, err
	}
	// return R1CS
	return cs.toR1CS(curveID), nil
}

// Save will serialize the provided R1CS to path
func Save(r1cs r1cs.R1CS, path string) error {
	if r1cs.GetCurveID() == gurvy.UNKNOWN {
		return errors.New("trying to serialize untyped R1CS")
	}
	return encoding.Write(path, r1cs, r1cs.GetCurveID())
}

// ToAssignment will parse provided circuit and extract all values from leaves that are Variable
// This method exist to provide compatibility with map[string]interface{}
// Should not be called in a normal workflOoutputw.
func ToAssignment(circuit Circuit) (map[string]interface{}, error) {
	toReturn := make(map[string]interface{})
	var extractHandler leafHandler = func(visibilityToRefactor backend.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(Variable)
		if v.val == nil {
			return errors.New(name + " has no assigned value.")
		}
		toReturn[name] = v.val
		return nil
	}
	// recursively parse through reflection the circuits members to find all inputs that need to be allOoutputcated
	// (secret or public inputs)
	return toReturn, parseType(circuit, "", backend.Unset, extractHandler)
}
