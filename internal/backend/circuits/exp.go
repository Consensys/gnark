package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type expCircuit struct {
	X, E frontend.Variable
	Y    frontend.Variable `gnark:",public"`
}

func (circuit *expCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	o := cs.ALLOCATE(1)
	b := cs.TO_BINARY(circuit.E, 4)

	var i int
	for i < len(b) {
		o = cs.MUL(o, o)
		mu := cs.MUL(o, circuit.X)
		o = cs.SELECT(b[len(b)-1-i], mu, o)
		i++
	}

	cs.MUSTBE_EQ(circuit.Y, o)
	return nil
}

func init() {
	var circuit, good, bad expCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.X.Assign(2)
	good.E.Assign(12)
	good.Y.Assign(4096)

	bad.X.Assign(2)
	bad.E.Assign(12)
	bad.Y.Assign(4095)

	addEntry("expo", r1cs, &good, &bad)
}
