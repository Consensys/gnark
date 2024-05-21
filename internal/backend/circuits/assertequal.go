package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type checkAssertEqualCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *checkAssertEqualCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func init() {

	var circuit, good, bad checkAssertEqualCircuit

	good.X = (3)
	good.Y = (3)

	bad.X = (5)
	bad.Y = (2)

	addEntry("assert_equal", &circuit, &good, &bad, nil)
}
