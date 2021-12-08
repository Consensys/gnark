package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type mul struct {
	A, B, C, D cs.Variable
	Z          cs.Variable `gnark:",public"`
}

func (circuit *mul) Define(api frontend.API) error {

	a := api.Mul(circuit.A, circuit.B, 3, circuit.C, "273823", circuit.D)
	api.AssertIsEqual(a, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad mul

	good.A = 6
	good.B = 2
	good.C = 123
	good.D = 76
	good.Z = 92149106544

	bad.A = 6
	bad.B = 2
	bad.C = 123
	bad.D = 76
	bad.Z = 1

	addEntry("mul", &circuit, &good, &bad, ecc.Implemented())
}
