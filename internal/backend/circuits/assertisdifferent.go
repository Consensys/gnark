package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type assertIsDifferentCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *assertIsDifferentCircuit) Define(api frontend.API) error {
	api.AssertIsDifferent(circuit.X, circuit.Y)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&assertIsDifferentCircuit{
			X: (6),
			Y: (37),
		},
	}

	bad := []frontend.Circuit{
		&assertIsDifferentCircuit{
			X: (6),
			Y: (6),
		},
	}

	addNewEntry("assert_different", &assertIsDifferentCircuit{}, good, bad, nil)
}
