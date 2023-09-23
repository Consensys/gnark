package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type determinism struct {
	X [5]frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (circuit *determinism) Define(api frontend.API) error {
	a := api.Add(circuit.X[0],
		circuit.X[0],
		circuit.X[1],
		circuit.X[1],
		circuit.X[2],
		circuit.X[2],
		circuit.X[3],
		circuit.X[3],
		circuit.X[4],
		circuit.X[4],
	)
	b := api.Mul(a, a)
	api.AssertIsEqual(b, circuit.Z)
	return nil
}

func init() {
	var circuit, good, bad determinism

	good.X[0] = (1)
	good.X[1] = (2)
	good.X[2] = (3)
	good.X[3] = (4)
	good.X[4] = (5)
	good.Z = (900)

	bad.X[0] = (1)
	bad.X[1] = (1)
	bad.X[2] = (1)
	bad.X[3] = (1)
	bad.X[4] = (1)
	bad.Z = (900)

	addEntry("determinism", &circuit, &good, &bad, nil)
}
