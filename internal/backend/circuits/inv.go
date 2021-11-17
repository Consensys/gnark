package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type invCircuit struct {
	X, Y, Z frontend.Variable
}

func (circuit *invCircuit) Define(cs frontend.API) error {
	m := cs.Mul(circuit.X, circuit.Y)
	u := cs.Inverse(circuit.Y)
	v := cs.Mul(m, u)
	cs.AssertIsEqual(v, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad invCircuit

	good.X = (6)
	good.Y = (12)
	good.Z = (6)

	bad.X = (4)
	bad.Y = (12)
	bad.Z = (5)

	addEntry("inv", &circuit, &good, &bad)
}
