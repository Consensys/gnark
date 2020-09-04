package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type lut00Circuit struct {
	B0, B1 frontend.Variable
	Z      frontend.Variable `gnark:",public"`
}

func (circuit *lut00Circuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	cs.MustBeBoolean(circuit.B0)
	cs.MustBeBoolean(circuit.B1)

	var lookuptable [4]big.Int

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := cs.SelectLUT(circuit.B1, circuit.B0, lookuptable)

	cs.MustBeEqual(r, circuit.Z)
	return nil
}

func init() {
	var circuit, good, bad lut00Circuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.B0.Assign(0)
	good.B1.Assign(0)
	good.Z.Assign(10)

	bad.B0.Assign(0)
	bad.B1.Assign(0)
	bad.Z.Assign(11)

	addEntry("lut00", r1cs, &good, &bad)
}
