package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type negCircuit struct {
	X frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (circuit *negCircuit) Define(cs frontend.API) error {
	a := cs.Mul(circuit.X, circuit.X)
	b := cs.Neg(circuit.X)
	c := cs.Add(a, b)
	cs.AssertIsEqual(c, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad negCircuit

	good.X = (6)
	good.Z = (30)

	bad.X = (7)
	bad.Z = (30)

	addEntry("neg", &circuit, &good, &bad)
}
