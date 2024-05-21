package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type subCircuit struct {
	A, B, C, D, E frontend.Variable
	Res           frontend.Variable `gnark:",public"`
}

func (circuit *subCircuit) Define(api frontend.API) error {

	a := api.Sub(23820938283, circuit.A, circuit.B, 232, circuit.C, "2039", circuit.D)
	api.AssertIsEqual(a, circuit.Res)

	b := api.Sub(circuit.E, circuit.A, circuit.B, 232, circuit.C, "2039", circuit.D)
	api.AssertIsEqual(b, circuit.Res)

	return nil
}

func init() {

	var circuit, good, bad subCircuit

	good.A = 6
	good.B = 2
	good.C = 123
	good.D = 76
	good.E = 23820938283
	good.Res = 23820935805

	bad.A = 6
	bad.B = 2
	bad.C = 123
	bad.D = 76
	bad.E = 23820938283
	bad.Res = 1

	addEntry("sub", &circuit, &good, &bad, nil)
}
