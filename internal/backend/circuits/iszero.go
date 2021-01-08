package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type isZero struct {
	X, Y frontend.Variable
}

func (circuit *isZero) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {

	a := cs.IsZero(circuit.X, gurvy.BN256)
	b := cs.IsZero(circuit.Y, gurvy.BN256)
	cs.AssertIsEqual(a, 1)
	cs.AssertIsEqual(b, 0)

	return nil
}

func init() {

	var circuit, good, bad, public isZero
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.X.Assign(203028)
	good.Y.Assign(0)

	bad.X.Assign(0)
	bad.Y.Assign(23)

	addEntry("isZero", r1cs, &good, &bad, &public)
}
