package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type isZero struct {
	X, Y frontend.Variable
}

func (circuit *isZero) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {

	a := cs.IsZero(circuit.X, curveID)
	b := cs.IsZero(circuit.Y, curveID)
	cs.AssertIsEqual(a, 1)
	cs.AssertIsEqual(b, 0)

	return nil
}

func init() {

	var circuit, good, bad, public isZero

	good.X.Assign(0)
	good.Y.Assign(203028)

	bad.X.Assign(23)
	bad.Y.Assign(0)

	addEntry("isZero", &circuit, &good, &bad, &public)
}
