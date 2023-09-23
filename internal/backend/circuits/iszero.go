package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type isZero struct {
	X, Y frontend.Variable
}

func (circuit *isZero) Define(api frontend.API) error {

	a := api.IsZero(circuit.X)
	b := api.IsZero(circuit.Y)
	c := api.IsZero(1)
	d := api.IsZero(0)
	api.AssertIsEqual(a, 1)
	api.AssertIsEqual(b, 0)
	api.AssertIsEqual(c, 0)
	api.AssertIsEqual(d, 1)

	return nil
}

func init() {

	var circuit, good, bad isZero

	good.X = (0)
	good.Y = (203028)

	bad.X = (23)
	bad.Y = (0)

	addEntry("isZero", &circuit, &good, &bad, nil)
}
