package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type determinism struct {
	X [5]frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (circuit *determinism) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	a := cs.Add(circuit.X[0],
		circuit.X[0],
		circuit.X[1],
		circuit.X[1],
		circuit.X[2],
		circuit.X[2],
		circuit.X[3],
		circuit.X[3],
		circuit.X[4],
		circuit.X[4],
	)
	b := cs.Mul(a, a)
	cs.AssertIsEqual(b, circuit.Z)
	return nil
}

func init() {
	var circuit, good, bad determinism

	good.X[0].Assign(1)
	good.X[1].Assign(2)
	good.X[2].Assign(3)
	good.X[3].Assign(4)
	good.X[4].Assign(5)
	good.Z.Assign(900)

	bad.X[0].Assign(1)
	bad.X[1].Assign(1)
	bad.X[2].Assign(1)
	bad.X[3].Assign(1)
	bad.X[4].Assign(1)
	bad.Z.Assign(900)

	addEntry("determinism", &circuit, &good, &bad)
}
