package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type invCircuit struct {
	X, Y, Z cs.Variable
}

func (circuit *invCircuit) Define(api frontend.API) error {
	m := api.Mul(circuit.X, circuit.Y)
	u := api.Inverse(circuit.Y)
	v := api.Mul(m, u)
	api.AssertIsEqual(v, circuit.Z)
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
