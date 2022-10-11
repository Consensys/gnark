// Package circuits contains test circuits
package circuits

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/nume-crypto/gnark-crypto/ecc"
)

// TestCircuit are used for test purposes (backend.Groth16 and gnark/integration_test.go)
type TestCircuit struct {
	Circuit                              frontend.Circuit
	ValidAssignments, InvalidAssignments []frontend.Circuit // good and bad witness for the prover + public verifier data
	HintFunctions                        []hint.Function
	Curves                               []ecc.ID
}

// Circuits are used for test purposes (backend.Groth16 and gnark/integration_test.go)
var Circuits map[string]TestCircuit

func addEntry(name string, circuit, proverGood, proverBad frontend.Circuit, curves []ecc.ID) {

	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}

	Circuits[name] = TestCircuit{circuit, []frontend.Circuit{proverGood}, []frontend.Circuit{proverBad}, nil, curves}
}

func addNewEntry(name string, circuit frontend.Circuit, proverGood, proverBad []frontend.Circuit, curves []ecc.ID, hintFunctions ...hint.Function) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}

	Circuits[name] = TestCircuit{circuit, proverGood, proverBad, hintFunctions, curves}
}
