package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type negCircuit struct {
	X frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (circuit *negCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	a := cs.Neg(circuit.X)
	b := cs.Add(a, circuit.X)
	cs.AssertIsEqual(b, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad, public negCircuit

	good.X.Assign(6)
	good.Z.Assign(0)

	bad.X.Assign(4)
	bad.Z.Assign(1)

	public.Z.Assign(0)

	addEntry("neg", &circuit, &good, &bad, &public)
}
