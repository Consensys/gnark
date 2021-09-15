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
	a := cs.Mul(circuit.X, circuit.X)
	b := cs.Neg(circuit.X)
	c := cs.Add(a, b)
	cs.AssertIsEqual(c, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad negCircuit

	good.X.Assign(6)
	good.Z.Assign(30)

	bad.X.Assign(7)
	bad.Z.Assign(30)

	addEntry("neg", &circuit, &good, &bad)
}
