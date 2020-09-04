package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type constantOpsCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *constantOpsCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	elmts := make([]big.Int, 3)
	for i := 0; i < 3; i++ {
		elmts[i].SetUint64(uint64(i) + 10)
	}
	c := cs.Add(circuit.X, elmts[0])
	c = cs.Mul(c, elmts[1])
	c = cs.Sub(c, elmts[2])
	cs.MustBeEqual(c, circuit.Y)
	return nil
}

func init() {
	var circuit, good, bad constantOpsCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.X.Assign(12)
	good.Y.Assign(230)

	bad.X.Assign(12)
	bad.Y.Assign(228)

	addEntry("constant_ops", r1cs, &good, &bad)
}
