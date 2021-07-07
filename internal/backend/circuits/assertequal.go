package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type checkAssertEqualCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *checkAssertEqualCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.Mul(circuit.X, circuit.X) // dummy constraint to ensure the number of constraints+assertions is >= 8
	cs.AssertIsEqual(circuit.X, circuit.Y)
	c1 := cs.Add(circuit.X, circuit.Y)
	cs.AssertIsEqual(c1, 6)
	return nil
}

func init() {

	var circuit, good, bad, public checkAssertEqualCircuit

	good.X.Assign(3)
	good.Y.Assign(3)

	bad.X.Assign(5)
	bad.Y.Assign(2)

	public.Y.Assign(3)

	addEntry("assert_equal", &circuit, &good, &bad, &public)
}
