package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type assertIsDifferentCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *assertIsDifferentCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	cs.AssertIsDifferent(circuit.X, circuit.Y)
	return nil
}

func init() {

	good := []frontend.Circuit{
		&assertIsDifferentCircuit{
			X: frontend.Value(6),
			Y: frontend.Value(37),
		},
	}

	bad := []frontend.Circuit{
		&assertIsDifferentCircuit{
			X: frontend.Value(6),
			Y: frontend.Value(6),
		},
	}

	addNewEntry("assert_different", &assertIsDifferentCircuit{}, good, bad)
}
