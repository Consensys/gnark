package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type mul struct {
	A, B, C, D frontend.Variable
	Z, ZZ      frontend.Variable `gnark:",public"`
}

func (circuit *mul) Define(api frontend.API) error {

	a := api.Mul(circuit.A, circuit.B, 3, circuit.C, "273823", circuit.D)
	b := api.Mul(circuit.A, circuit.A, 0)
	api.AssertIsEqual(a, circuit.Z)
	api.AssertIsEqual(b, 0)
	api.AssertIsEqual(b, circuit.ZZ)
	return nil
}

func init() {

	var circuit, good, bad mul

	good.A = 6
	good.B = 2
	good.C = 123
	good.D = 76
	good.Z = 92149106544
	good.ZZ = 0

	bad.A = 6
	bad.B = 2
	bad.C = 123
	bad.D = 76
	bad.Z = 1
	bad.ZZ = 1

	addEntry("mul", &circuit, &good, &bad, nil)
}
