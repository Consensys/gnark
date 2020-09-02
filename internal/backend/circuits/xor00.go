package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type xorCircuit struct {
	B0, B1 frontend.Variable
	Y0     frontend.Variable `gnark:",public"`
}

func (circuit *xorCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	cs.MUSTBE_BOOLEAN(circuit.B0)
	cs.MUSTBE_BOOLEAN(circuit.B1)

	z0 := cs.XOR(circuit.B0, circuit.B1)

	cs.MUSTBE_EQ(z0, circuit.Y0)

	return nil
}

func init() {
	var circuit, good, bad xorCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.B0.Assign(0)
	good.B1.Assign(0)
	good.Y0.Assign(0)

	bad.B0.Assign(0)
	bad.B1.Assign(0)
	bad.Y0.Assign(1)

	addEntry("xor00", r1cs, &good, &bad)
}
