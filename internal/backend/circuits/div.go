package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type divCircuit struct {
	X, Y frontend.Variable
	Z    frontend.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(cs frontend.API) error {
	cs.AssertIsEqual(cs.DivUnchecked(circuit.X, circuit.Y), circuit.Z)
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
