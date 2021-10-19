package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type divCircuit struct {
	X, Y frontend.Variable
	Z    frontend.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	cs.AssertIsEqual(cs.Div(circuit.X, circuit.Y), circuit.Z)
	return nil
}

func init() {
	var good, bad divCircuit

	good.X.Assign(12)
	good.Y.Assign(6)
	good.Z.Assign(2)

	bad.X.Assign(12)
	bad.Y.Assign(6)
	bad.Z.Assign(3)

	addEntry("div", &divCircuit{}, &good, &bad)
}
