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

	good.X.Assign(203028)
	good.Y.Assign(0)

	bad.X.Assign(0)
	bad.Y.Assign(23)

	addEntry("isZero", &circuit, &good, &bad, &public)
}
