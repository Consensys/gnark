package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type expCircuit struct {
	X, E frontend.Variable
	Y    frontend.Variable `gnark:",public"`
}

func (circuit *expCircuit) Define(api frontend.API) error {
	o := frontend.Variable(1)
	b := api.ToBinary(circuit.E, 4)

	var i int
	for i < len(b) {
		o = api.Mul(o, o)
		mu := api.Mul(o, circuit.X)
		o = api.Select(b[len(b)-1-i], mu, o)
		i++
	}
	api.AssertIsEqual(circuit.Y, o)
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

	addEntry("expo", &circuit, &good, &bad, nil)
}
