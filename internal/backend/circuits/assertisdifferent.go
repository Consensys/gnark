package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type assertIsDifferentCircuit struct {
	X cs.Variable
	Y cs.Variable `gnark:",public"`
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

	addNewEntry("assert_different", &assertIsDifferentCircuit{}, good, bad, ecc.Implemented())
}
