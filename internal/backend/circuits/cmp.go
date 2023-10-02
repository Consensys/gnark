package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type cmpCircuit struct {
	A frontend.Variable
	B frontend.Variable `gnark:",public"`
	R frontend.Variable
}

func (circuit *cmpCircuit) Define(api frontend.API) error {
	r := api.Cmp(circuit.A, circuit.B)
	api.AssertIsEqual(r, circuit.R)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&cmpCircuit{
			A: 12346,
			B: 12345,
			R: 1,
		},
		&cmpCircuit{
			A: 12345,
			B: 12346,
			R: -1,
		},
		&cmpCircuit{
			A: 12345,
			B: 12345,
			R: 0,
		},
	}

	bad := []frontend.Circuit{
		&cmpCircuit{
			A: 12345,
			B: 12346,
			R: 1,
		},
		&cmpCircuit{
			A: 12346,
			B: 12345,
			R: -1,
		},
		&cmpCircuit{
			A: 12345,
			B: 12345,
			R: 1,
		},
	}

	addNewEntry("cmp", &cmpCircuit{}, good, bad, nil)
}
