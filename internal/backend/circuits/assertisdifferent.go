package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type assertIsDifferentCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *assertIsDifferentCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	m := cs.Mul(circuit.X, circuit.X)
	cs.AssertIsDifferent(m, circuit.Y)
	return nil
}

func init() {
	var circuit, good, bad assertIsDifferentCircuit

	// expected Z
	var expectedZ big.Int
	expectedZ.SetUint64(3)

	good.X.Assign(6)
	good.Y.Assign(37)

	bad.X.Assign(6)
	bad.Y.Assign(36)

	addEntry("assert_different", &circuit, &good, &bad)
}
