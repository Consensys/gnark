// Package circuits contains test circuits
package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// TestCircuit are used for test purposes (backend.Groth16 and gnark/integration_test.go)
type TestCircuit struct {
	Circuit                              frontend.Circuit
	ValidAssignments, InvalidAssignments []frontend.Circuit // good and bad witness for the prover + public verifier data
	HintFunctions                        []solver.Hint
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

	Circuits[name] = TestCircuit{Circuit: circuit, ValidAssignments: []frontend.Circuit{proverGood}, InvalidAssignments: []frontend.Circuit{proverBad}, HintFunctions: nil, Curves: curves}
}

func addNewEntry(name string, circuit frontend.Circuit, proverGood, proverBad []frontend.Circuit, curves []ecc.ID, hintFunctions ...solver.Hint) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}
	solver.RegisterHint(hintFunctions...)

	Circuits[name] = TestCircuit{Circuit: circuit, ValidAssignments: proverGood, InvalidAssignments: proverBad, HintFunctions: nil, Curves: curves}
}
