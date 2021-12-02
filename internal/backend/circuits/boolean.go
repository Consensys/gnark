package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type checkAssertIsBooleanCircuit struct {
	A, B, C frontend.Variable
}

func (circuit *checkAssertIsBooleanCircuit) Define(cs frontend.API) error {

	// simple variable
	cs.AssertIsBoolean(circuit.C)

	// linear expression ADD
	cs.AssertIsBoolean(cs.Add(circuit.A, circuit.B))

	// linear expression SUB
	cs.AssertIsBoolean(cs.Sub(circuit.A, circuit.B))

	return nil
}

func init() {

	good := []frontend.Circuit{
		&checkAssertIsBooleanCircuit{
			A: (0),
			B: (0),
			C: (1),
		},
		&checkAssertIsBooleanCircuit{
			A: (0),
			B: (0),
			C: (0),
		},
		&checkAssertIsBooleanCircuit{
			A: (1),
			B: (0),
			C: (1),
		},
		&checkAssertIsBooleanCircuit{
			A: (1),
			B: (0),
			C: (0),
		},
	}

	bad := []frontend.Circuit{
		&checkAssertIsBooleanCircuit{
			A: (1),
			B: (1),
			C: (0),
		},
		&checkAssertIsBooleanCircuit{
			A: (0),
			B: (1),
			C: (0),
		},
		&checkAssertIsBooleanCircuit{
			A: (0),
			B: (0),
			C: (3),
		},
		&checkAssertIsBooleanCircuit{
			A: (1),
			B: (0),
			C: (3),
		},
	}

	addNewEntry("assert_boolean", &checkAssertIsBooleanCircuit{}, good, bad)
}
