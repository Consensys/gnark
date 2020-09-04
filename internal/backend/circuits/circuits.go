// Package circuits contains test circuits
package circuits

import (
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
)

// TestCircuit are used for test purposes (backend.Groth16 and gnark/integration_test.go)
type TestCircuit struct {
	R1CS      *r1cs.UntypedR1CS
	Good, Bad map[string]interface{}
}

// Circuits are used for test purposes (backend.Groth16 and gnark/integration_test.go)
var Circuits map[string]TestCircuit

func addEntry(name string, R1CS r1cs.R1CS, _good, _bad frontend.Circuit) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}
	good, err := frontend.ToAssignment(_good)
	if err != nil {
		panic("invalid good assignment:" + err.Error())
	}
	bad, err := frontend.ToAssignment(_bad)
	if err != nil {
		panic("invalid bad assignment:" + err.Error())
	}
	Circuits[name] = TestCircuit{R1CS.(*r1cs.UntypedR1CS), good, bad}
}
