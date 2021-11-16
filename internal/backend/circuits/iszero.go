package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type isZero struct {
	X, Y frontend.Variable
}

func (circuit *isZero) Define(curveID ecc.ID, cs frontend.API) error {

	a := cs.IsZero(circuit.X)
	b := cs.IsZero(circuit.Y)
	cs.AssertIsEqual(a, 1)
	cs.AssertIsEqual(b, 0)

	return nil
}

func init() {

	var circuit, good, bad isZero

	good.X = (0)
	good.Y = (203028)

	bad.X = (23)
	bad.Y = (0)

	addEntry("isZero", &circuit, &good, &bad)
}
