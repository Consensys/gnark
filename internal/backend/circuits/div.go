package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type divCircuit struct {
	X, Y cs.Variable
	Z    cs.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.DivUnchecked(circuit.X, circuit.Y), circuit.Z)
	return nil
}

func init() {
	var good, bad divCircuit

	good.X = (12)
	good.Y = (6)
	good.Z = (2)

	bad.X = (12)
	bad.Y = (6)
	bad.Z = (3)

	addEntry("div", &divCircuit{}, &good, &bad)
}
