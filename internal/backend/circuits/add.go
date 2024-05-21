package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type addCircuit struct {
	A, B, C, D frontend.Variable
	Z          frontend.Variable `gnark:",public"`
}

func (circuit *addCircuit) Define(api frontend.API) error {

	a := api.Add(circuit.A, circuit.B, 3, circuit.C, "273823", circuit.D)
	b := api.Add(circuit.A, 2)
	c := api.Add(2, circuit.A)
	d := api.Add(circuit.B, circuit.A)
	api.AssertIsEqual(a, circuit.Z)
	api.AssertIsEqual(b, 8)
	api.AssertIsEqual(c, 8)
	api.AssertIsEqual(d, 8)
	return nil
}

func init() {

	var circuit, good, bad addCircuit

	good.A = 6
	good.B = 2
	good.C = 123
	good.D = 76
	good.Z = 274033

	bad.A = 6
	bad.B = 2
	bad.C = 123
	bad.D = 76
	bad.Z = 1

	addEntry("add", &circuit, &good, &bad, nil)
}
