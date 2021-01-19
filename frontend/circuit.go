package frontend

import (
	"errors"
	"reflect"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/internal/parser"
	"github.com/consensys/gurvy"
)

// Circuit must be implemented by user-defined circuits
//
// the tag format is as follow:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"name,option"`
// 		}
// if empty, default resolves to variable name (here "Y") and secret visibility
// similarly to json or xml struct tags, these are valid:
// 		`gnark:",public"` or `gnark:"-"`
// using "-" marks the variable as ignored by the Compile method. This can be useful when you need to
// declare variables as aliases that are already allocated. For example
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:",public"`
//			Z frontend.Variable `gnark:"-"`
// 		}
// it is then the developer responsability to do circuit.Z = circuit.Y in the Define() method
type Circuit interface {
	// Define declares the circuit's Constraints
	Define(curveID gurvy.ID, cs *ConstraintSystem) error
}

// Witness embedds Circuit interface, used to distinguish APIs
// that expect a Witness (with assigned values) versus a Circuit
type Witness interface {
	Circuit
}

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
func Compile(curveID gurvy.ID, circuit Circuit) (r1cs.R1CS, error) {

	// instantiate our constraint system
	cs := newConstraintSystem()

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	var handler parser.LeafHandler = func(visibility backend.Visibility, name string, tInput reflect.Value) error {
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
			case backend.Unset, backend.Secret:
				tInput.Set(reflect.ValueOf(cs.newSecretVariable()))
			case backend.Public:
				tInput.Set(reflect.ValueOf(cs.newPublicVariable()))
			}

			return nil
		}
		return errors.New("can't set val " + name)
	}
	// recursively parse through reflection the circuits members to find all Constraints that need to be allOoutputcated
	// (secret or public inputs)
	if err := parser.Visit(circuit, "", backend.Unset, handler, reflect.TypeOf(Variable{})); err != nil {
		return nil, err
	}

	// call Define() to fill in the Constraints
	if err := circuit.Define(curveID, &cs); err != nil {
		return nil, err
	}
	// return R1CS
	//return cs.toR1CS(curveID), nil
	res, err := cs.toR1CS(curveID)
	if err != nil {
		return nil, err
	}

	return res, nil
}
