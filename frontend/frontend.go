// Package frontend contains the object and logic to define and compile gnark circuits
package frontend

import (
	"errors"
	"reflect"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
	"github.com/consensys/gurvy"
)

// ErrInputNotSet triggered when trying to access a variable that was not allocated
var ErrInputNotSet = errors.New("variable is not allocated")

// Compile will generate a R1CS from the given circuit
//
// 1. it will first allocate the user inputs (see type Tag for more info)
// example:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"exponent,public"`
// 		}
// in that case, Compile() will allocate one public variable with id "exponent"
//
// 2. it then calls circuit.Define(curveID, constraintSystem) to build the internal constraint system
// from the declarative code
//
// 3. finally, it converts that to a R1CS
func Compile(curveID gurvy.ID, zkpID backend.ID, circuit Circuit) (ccs CompiledConstraintSystem, err error) {

	// build the constraint system (see Circuit.Define)
	cs, err := buildCS(curveID, circuit)
	if err != nil {
		return nil, err
	}

	// offset the IDs -> interal_wire || secret_variables || public_variables
	switch zkpID {
	case backend.GROTH16:
		ccs, err = cs.toR1CS(curveID)
	case backend.PLONK:
		ccs, err = cs.toSparseR1CS(curveID)
	default:
		panic("not implemented")
	}
	if err != nil {
		return nil, err
	}

	return
}

// buildCS builds the constraint system. It bootstraps the inputs
// allocations by parsing the circuit's underlying structure, then
// it builds the constraint system using the Define method.
func buildCS(curveID gurvy.ID, circuit Circuit) (ConstraintSystem, error) {

	// instantiate our constraint system
	cs := newConstraintSystem()

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	var handler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if tInput.CanSet() {
			v := tInput.Interface().(Variable)
			if v.id != 0 {
				v.id = 0
				// return errors.New("circuit was already compiled")
			}
			if v.val != nil {
				return errors.New("circuit has some assigned values, can't compile")
			}
			switch visibility {
			case compiled.Unset, compiled.Secret:
				tInput.Set(reflect.ValueOf(cs.newSecretVariable()))
			case compiled.Public:
				tInput.Set(reflect.ValueOf(cs.newPublicVariable()))
			}

			return nil
		}
		return errors.New("can't set val " + name)
	}
	// recursively parse through reflection the circuits members to find all Constraints that need to be allOoutputcated
	// (secret or public inputs)
	if err := parser.Visit(circuit, "", compiled.Unset, handler, reflect.TypeOf(Variable{})); err != nil {
		return cs, err
	}

	// call Define() to fill in the Constraints
	if err := circuit.Define(curveID, &cs); err != nil {
		return cs, err
	}

	return cs, nil

}
