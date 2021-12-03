/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package frontend

import (
	// "plonk"
	// "r1cs"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend/plonk"
	"github.com/consensys/gnark/frontend/r1cs"
)

// Compile will generate a CompiledConstraintSystem from the given circuit
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
// 3. finally, it converts that to a CompiledConstraintSystem.
// 		if zkpID == backend.GROTH16	--> R1CS
//		if zkpID == backend.PLONK 	--> SparseR1CS
//
// initialCapacity is an optional parameter that reserves memory in slices
// it should be set to the estimated number of constraints in the circuit, if known.
func RefactorCompile(curveID ecc.ID, zkpID backend.ID, circuit Circuit, opts ...func(opt *CompileOption) error) (ccs CompiledConstraintSystem, err error) {

	// setup option
	opt := CompileOption{}
	for _, o := range opts {
		if err := o(&opt); err != nil {
			return nil, err
		}
	}

	var system System

	switch zkpID {
	case backend.GROTH16:
		system = r1cs.NewR1CSRefactor(curveID, zkpID)
	case backend.PLONK:
		system = plonk.NewSparseR1CS(curveID, zkpID)
	default:
		panic("not implemented")
	}

	// build the constraint system (see Circuit.Define)
	err = bootLoad(curveID, zkpID, circuit, system, opt.capacity)
	if err != nil {
		return nil, err
	}

	// ensure all inputs and hints are constrained
	// if !opt.ignoreUnconstrainedInputs {
	// 	if err := cs.checkVariables(); err != nil {
	// 		return nil, err
	// 	}
	// }

	// switch zkpID {
	// case backend.GROTH16:
	// 	ccs, err = cs.toR1CS(curveID)
	// case backend.PLONK:
	// 	ccs, err = cs.toSparseR1CS(curveID)
	// default:
	// 	panic("not implemented")
	// }

	// if err != nil {
	// 	return nil, err
	// }

	return
}

// buildCS builds the constraint system. It bootstraps the inputs
// allocations by parsing the circuit's underlying structure, then
// it builds the constraint system using the Define method.
func bootLoad(curveID ecc.ID, zkpID backend.ID, circuit Circuit, system System, initialCapacity ...int) error {

	// leaf handlers are called when encoutering leafs in the circuit data struct
	// leafs are Constraints that need to be initialized in the context of compiling a circuit
	// var handler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
	// 	if tInput.CanSet() {
	// 		switch visibility {
	// 		case compiled.Secret:
	// 			tInput.Set(reflect.ValueOf(system.NewSecretVariable(name)))
	// 		case compiled.Public:
	// 			tInput.Set(reflect.ValueOf(system.NewPublicVariable(name)))
	// 		case compiled.Unset:
	// 			return errors.New("can't set val " + name + " visibility is unset")
	// 		}

	// 		return nil
	// 	}
	// 	return errors.New("can't set val " + name)
	// }
	// // recursively parse through reflection the circuits members to find all Constraints that need to be allOoutputcated
	// // (secret or public inputs)
	// if err := parser.Visit(circuit, "", compiled.Unset, handler, tVariable); err != nil {
	// 	return cs, err
	// }

	// // recover from panics to print user-friendlier messages
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		err = fmt.Errorf("%v\n%s", r, debug.Stack())
	// 	}
	// }()

	// // call Define() to fill in the Constraints
	// if err := circuit.Define(&cs); err != nil {
	// 	return cs, err
	// }

	return nil

}
