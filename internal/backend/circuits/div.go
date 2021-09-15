package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type divCircuit struct {
	X, Y frontend.Variable
	Z    frontend.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	m := cs.Mul(circuit.X, circuit.X)
	d := cs.Div(m, circuit.Y)
	cs.AssertIsEqual(d, circuit.Z)
	return nil
}

func init() {
	var circuit, good, bad divCircuit

	// expected Z
	var expectedZ big.Int
	expectedZ.SetUint64(3)

	good.X.Assign(6)
	good.Y.Assign(12)
	good.Z.Assign(expectedZ)

	bad.X.Assign(4)
	bad.Y.Assign(10)
	bad.Z.Assign(expectedZ)

	addEntry("div", &circuit, &good, &bad)
}
