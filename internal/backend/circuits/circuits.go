// Package circuits contains test circuits
package circuits

import (
	"github.com/consensys/gnark/frontend"
)

// TestCircuit are used for test purposes (backend.Groth16 and gnark/integration_test.go)
type TestCircuit struct {
	Circuit                          frontend.Circuit
	ValidWitnesses, InvalidWitnesses []frontend.Circuit // good and bad witness for the prover + public verifier data
}

// Circuits are used for test purposes (backend.Groth16 and gnark/integration_test.go)
var Circuits map[string]TestCircuit

func addEntry(name string, circuit, proverGood, proverBad frontend.Circuit) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}

	Circuits[name] = TestCircuit{circuit, []frontend.Circuit{proverGood}, []frontend.Circuit{proverBad}}
}

func addNewEntry(name string, circuit frontend.Circuit, proverGood, proverBad []frontend.Circuit) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}

	Circuits[name] = TestCircuit{circuit, proverGood, proverBad}
}
