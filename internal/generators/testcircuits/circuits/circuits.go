// This package contains test circuits
package circuits

import (
	"github.com/consensys/gnark/backend"
)

type TestCircuit struct {
	R1CS      *backend.R1CS
	Good, Bad backend.Assignments
}

var Circuits map[string]TestCircuit

func addEntry(name string, r1cs *backend.R1CS, good, bad backend.Assignments) {
	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}
	Circuits[name] = TestCircuit{r1cs, good, bad}
}
