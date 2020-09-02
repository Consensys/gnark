package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type lut10Circuit struct {
	B0, B1 frontend.Variable
	Z      frontend.Variable `gnark:",public"`
}

func (circuit *lut10Circuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	cs.MUSTBE_BOOLEAN(circuit.B0)
	cs.MUSTBE_BOOLEAN(circuit.B1)

	var lookuptable [4]big.Int

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := cs.SELECT_LUT(circuit.B1, circuit.B0, lookuptable)

	cs.MUSTBE_EQ(r, circuit.Z)
	return nil
}

func init() {
	var circuit, good, bad lut10Circuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.B0.Assign(0)
	good.B1.Assign(1)
	good.Z.Assign(22)

	bad.B0.Assign(0)
	bad.B1.Assign(1)
	bad.Z.Assign(11)

	addEntry("lut10", r1cs, &good, &bad)
}
