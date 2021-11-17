package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type expCircuit struct {
	X, E frontend.Variable
	Y    frontend.Variable `gnark:",public"`
}

func (circuit *expCircuit) Define(cs frontend.API) error {
	o := frontend.Variable(1)
	b := cs.ToBinary(circuit.E, 4)

	var i int
	for i < len(b) {
		o = cs.Mul(o, o)
		mu := cs.Mul(o, circuit.X)
		o = cs.Select(b[len(b)-1-i], mu, o)
		i++
	}
	cs.AssertIsEqual(circuit.Y, o)
	return nil
}

func init() {
	var circuit, good, bad expCircuit

	good.X = (2)
	good.E = (12)
	good.Y = (4096)

	bad.X = (2)
	bad.E = (11)
	bad.Y = (4096)

	addEntry("expo", &circuit, &good, &bad)
}
