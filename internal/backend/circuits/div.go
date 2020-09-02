package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type divCircuit struct {
	X, Y frontend.Variable
	Z    frontend.Variable `gnark:",public"`
}

func (circuit *divCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	m := cs.MUL(circuit.X, circuit.X)
	d := cs.DIV(m, circuit.Y)
	cs.MUSTBE_EQ(d, circuit.Z)
	return nil
}

func init() {
	var circuit, good, bad divCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	// expected Z
	var expectedZ big.Int
	expectedZ.SetUint64(3)

	good.X.Assign(6)
	good.Y.Assign(12)
	good.Z.Assign(expectedZ)

	bad.X.Assign(4)
	bad.Y.Assign(10)
	bad.Z.Assign(42)

	addEntry("div", r1cs, &good, &bad)
}
