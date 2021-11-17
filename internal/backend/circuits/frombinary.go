package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type fromBinaryCircuit struct {
	B0, B1, B2, B3 frontend.Variable
	Y              frontend.Variable `gnark:",public"`
}

func (circuit *fromBinaryCircuit) Define(cs frontend.API) error {
	cs.AssertIsBoolean(circuit.B0)
	cs.AssertIsBoolean(circuit.B1)
	cs.AssertIsBoolean(circuit.B2)
	cs.AssertIsBoolean(circuit.B3)

	r := cs.FromBinary(circuit.B0, circuit.B1, circuit.B2, circuit.B3)

	cs.AssertIsEqual(circuit.Y, r)
	return nil
}

func init() {
	var circuit, good, bad fromBinaryCircuit

	good.B0 = (1)
	good.B1 = (0)
	good.B2 = (1)
	good.B3 = (1)
	good.Y = (13)

	bad.B0 = (1)
	bad.B1 = (0)
	bad.B2 = (0)
	bad.B3 = (1)
	bad.Y = (13)

	addEntry("frombinary", &circuit, &good, &bad)
}
