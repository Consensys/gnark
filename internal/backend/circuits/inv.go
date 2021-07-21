package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type invCircuit struct {
	X, Y, Z frontend.Variable
}

func (circuit *invCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.Mul(circuit.X, circuit.X) // dummy constraint to ensure the number of constraints+assertions is >= 8
	m := cs.Mul(circuit.X, circuit.Y)
	u := cs.Inverse(circuit.Y)
	v := cs.Mul(m, u)
	cs.AssertIsEqual(v, circuit.Z)
	return nil
}

func init() {

	var circuit, good, bad, public invCircuit

	good.X.Assign(6)
	good.Y.Assign(12)
	good.Z.Assign(6)

	bad.X.Assign(4)
	bad.Y.Assign(12)
	bad.Z.Assign(5)

	addEntry("inv", &circuit, &good, &bad, &public)
}
