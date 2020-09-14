package frontend

import (
	"errors"
	"reflect"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs"
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
				tInput.Set(reflect.ValueOf(cs.newSecretVariable(name)))
			case backend.Public:
				tInput.Set(reflect.ValueOf(cs.newPublicVariable(name)))
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

// ParseWitness will returns a map[string]interface{} to be used as input in
// in R1CS.Solve(), groth16.Prove() or groth16.Verify()
// if input is not already a map[string]interface{}, it must implemenet frontend.Circuit
func ParseWitness(input interface{}) (map[string]interface{}, error) {
	switch c := input.(type) {
	case map[string]interface{}:
		return c, nil
	case Circuit:
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
		return toReturn, parseType(c, "", backend.Unset, extractHandler)
	default:
		rValue := reflect.ValueOf(input)
		if rValue.Kind() != reflect.Ptr {
			return nil, errors.New("input must be map[string]interface{} or implement frontend.Circuit (got a non-pointer value)")
		}
		return nil, errors.New("input must be map[string]interface{} or implement frontend.Circuit")
	}

}
