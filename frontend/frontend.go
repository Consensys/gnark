// Package frontend contains the object and logic to define and compile gnark circuits
package frontend

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// ErrInputNotSet triggered when trying to access a variable that was not allocated
var ErrInputNotSet = errors.New("variable is not allocated")

// Compile will generate a CompiledConstraintSystem from the given circuit
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
// 3. finally, it converts that to a CompiledConstraintSystem.
// 		if zkpID == backend.GROTH16	--> R1CS
//		if zkpID == backend.PLONK 	--> SparseR1CS
//
// initialCapacity is an optional parameter that reserves memory in slices
// it should be set to the estimated number of constraints in the circuit, if known.
func Compile(curveID ecc.ID, zkpID backend.ID, circuit Circuit, initialCapacity ...int) (ccs CompiledConstraintSystem, err error) {

	// build the constraint system (see Circuit.Define)
	cs, err := buildCS(curveID, circuit, initialCapacity...)
	if err != nil {
		return nil, err
	}

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
func buildCS(curveID ecc.ID, circuit Circuit, initialCapacity ...int) (cs ConstraintSystem, err error) {
	// recover from panics to print user-friendlier messages
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	// instantiate our constraint system
	cs = newConstraintSystem(initialCapacity...)

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
			case compiled.Secret:
				tInput.Set(reflect.ValueOf(cs.newSecretVariable()))
			case compiled.Public:
				tInput.Set(reflect.ValueOf(cs.newPublicVariable()))
			case compiled.Unset:
				return errors.New("can't set val " + name + " visibility is unset")
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

	return

}
