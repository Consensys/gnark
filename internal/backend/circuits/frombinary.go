package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type fromBinaryCircuit struct {
	B0, B1, B2, B3 frontend.Variable
	Y              frontend.Variable `gnark:",public"`
}

func (circuit *fromBinaryCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	cs.MUSTBE_BOOLEAN(circuit.B0)
	cs.MUSTBE_BOOLEAN(circuit.B1)
	cs.MUSTBE_BOOLEAN(circuit.B2)
	cs.MUSTBE_BOOLEAN(circuit.B3)

	r := cs.FROM_BINARY(circuit.B0, circuit.B1, circuit.B2, circuit.B3)

	cs.MUSTBE_EQ(circuit.Y, r)
	return nil
}

func init() {
	var circuit, good, bad fromBinaryCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.B0.Assign(1)
	good.B1.Assign(0)
	good.B2.Assign(1)
	good.B3.Assign(1)
	good.Y.Assign(13)

	bad.B0.Assign(1)
	bad.B1.Assign(0)
	bad.B2.Assign(1)
	bad.B3.Assign(1)
	bad.Y.Assign(12)

	addEntry("frombinary", r1cs, &good, &bad)
}
