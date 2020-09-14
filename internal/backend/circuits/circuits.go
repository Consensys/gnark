// Package circuits contains test circuits
package circuits

import (
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
)

// TestCircuit are used for test purposes (backend.Groth16 and gnark/integration_test.go)
type TestCircuit struct {
	R1CS      *r1cs.UntypedR1CS
	Good, Bad frontend.Circuit // good and bad witness
}

// Circuits are used for test purposes (backend.Groth16 and gnark/integration_test.go)
var Circuits map[string]TestCircuit

func addEntry(name string, R1CS r1cs.R1CS, good, bad frontend.Circuit) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}

	Circuits[name] = TestCircuit{R1CS.(*r1cs.UntypedR1CS), good, bad}
}
