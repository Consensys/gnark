// Package circuits contains test circuits
package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// TestCircuit are used for test purposes (backend.Groth16 and gnark/integration_test.go)
type TestCircuit struct {
	Circuit                              frontend.Circuit
	ValidAssignments, InvalidAssignments []frontend.Circuit // good and bad witness for the prover + public verifier data
	HintFunctions                        []solver.Hint
	Curves                               []ecc.ID
	ProverOptions                        []backend.ProverOption
	VerifierOptions                      []backend.VerifierOption
}

type TestCircuitOptionsFunc func(*TestCircuit)

func WithProverOpts(opts ...backend.ProverOption) TestCircuitOptionsFunc {
	return func(c *TestCircuit) {
		c.ProverOptions = append(c.ProverOptions, opts...)
	}
}

func WithVerifierOpts(opts ...backend.VerifierOption) TestCircuitOptionsFunc {
	return func(c *TestCircuit) {
		c.VerifierOptions = append(c.VerifierOptions, opts...)
	}
}

func applyOptions(c *TestCircuit, opts ...TestCircuitOptionsFunc) {
	for _, opt := range opts {
		opt(c)
	}
}

// Circuits are used for test purposes (backend.Groth16 and gnark/integration_test.go)
var Circuits map[string]TestCircuit

func addEntry(name string, circuit, proverGood, proverBad frontend.Circuit, curves []ecc.ID, opts ...TestCircuitOptionsFunc) {

	if Circuits == nil {
		Circuits = make(map[string]TestCircuit)
	}
	if _, ok := Circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}

	c := TestCircuit{Circuit: circuit, ValidAssignments: []frontend.Circuit{proverGood}, InvalidAssignments: []frontend.Circuit{proverBad}, HintFunctions: nil, Curves: curves}
	applyOptions(&c, opts...)

	Circuits[name] = c
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
