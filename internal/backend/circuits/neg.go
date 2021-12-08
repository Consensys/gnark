package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
)

type negCircuit struct {
	X cs.Variable
	Z cs.Variable `gnark:",public"`
}

func (circuit *negCircuit) Define(api frontend.API) error {
	a := api.Mul(circuit.X, circuit.X)
	b := api.Neg(circuit.X)
	c := api.Add(a, b)
	api.AssertIsEqual(c, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad negCircuit

	good.X = (6)
	good.Z = (30)

	bad.X = (7)
	bad.Z = (30)

	addEntry("neg", &circuit, &good, &bad, ecc.Implemented())
}
