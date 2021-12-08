package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type checkAssertIsBooleanCircuit struct {
	A, B, C cs.Variable
}

func (circuit *checkAssertIsBooleanCircuit) Define(api frontend.API) error {

	// simple variable
	api.AssertIsBoolean(circuit.C)

	// linear expression ADD
	api.AssertIsBoolean(api.Add(circuit.A, circuit.B))

	// linear expression SUB
	api.AssertIsBoolean(api.Sub(circuit.A, circuit.B))

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

	addNewEntry("assert_boolean", &checkAssertIsBooleanCircuit{}, good, bad, ecc.Implemented())
}
