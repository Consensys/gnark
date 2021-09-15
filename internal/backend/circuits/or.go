package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type orCircuit struct {
	Left  [4]frontend.Variable
	Right [4]frontend.Variable
	Res   [4]frontend.Variable
}

func (circuit *orCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	a := cs.Or(circuit.Left[0], circuit.Right[0])
	b := cs.Or(circuit.Left[1], circuit.Right[1])
	c := cs.Or(circuit.Left[2], circuit.Right[2])
	d := cs.Or(circuit.Left[3], circuit.Right[3])
	cs.AssertIsEqual(a, circuit.Res[0])
	cs.AssertIsEqual(b, circuit.Res[1])
	cs.AssertIsEqual(c, circuit.Res[2])
	cs.AssertIsEqual(d, circuit.Res[3])
	return nil
}

func init() {

	var circuit, good, bad orCircuit

	good.Left[0].Assign(0)
	good.Left[1].Assign(0)
	good.Left[2].Assign(1)
	good.Left[3].Assign(1)

	good.Right[0].Assign(0)
	good.Right[1].Assign(1)
	good.Right[2].Assign(0)
	good.Right[3].Assign(1)

	good.Res[0].Assign(0)
	good.Res[1].Assign(1)
	good.Res[2].Assign(1)
	good.Res[3].Assign(1)

	bad.Left[0].Assign(0)
	bad.Left[1].Assign(0)
	bad.Left[2].Assign(1)
	bad.Left[3].Assign(1)

	bad.Right[0].Assign(0)
	bad.Right[1].Assign(1)
	bad.Right[2].Assign(0)
	bad.Right[3].Assign(1)

	bad.Res[0].Assign(1)
	bad.Res[1].Assign(0)
	bad.Res[2].Assign(1)
	bad.Res[3].Assign(0)

	addEntry("OR", &circuit, &good, &bad)
}
