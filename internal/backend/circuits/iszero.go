package circuits

import (
	"github.com/consensys/gnark"
	"github.com/consensys/gnark/frontend"
)

type isZero struct {
	X, Y frontend.Variable
}

func (circuit *isZero) Define(api frontend.API) error {

	a := api.IsZero(circuit.X)
	b := api.IsZero(circuit.Y)
	api.AssertIsEqual(a, 1)
	api.AssertIsEqual(b, 0)

	return nil
}

func init() {

	var circuit, good, bad isZero

	good.X = (0)
	good.Y = (203028)

	bad.X = (23)
	bad.Y = (0)

	addEntry("isZero", &circuit, &good, &bad, gnark.Curves())
}
