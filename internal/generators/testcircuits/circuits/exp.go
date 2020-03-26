package circuits

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

func init() {
	circuit := frontend.New()

	x := circuit.SECRET_INPUT("x")
	e := circuit.SECRET_INPUT("e")
	y := circuit.PUBLIC_INPUT("y")

	o := circuit.ALLOCATE(1)
	b := circuit.TO_BINARY(e, 4)

	var i int
	for i < len(b) {
		o = circuit.MUL(o, o)
		mu := circuit.MUL(o, x)
		o = circuit.SELECT(b[len(b)-1-i], mu, o)
		i++
	}

	circuit.MUSTBE_EQ(y, o)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "x", 2)
	good.Assign(backend.Secret, "e", 12)
	good.Assign(backend.Public, "y", 4096)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "x", 2)
	bad.Assign(backend.Secret, "e", 12)
	bad.Assign(backend.Public, "y", 4095)

	r1cs := circuit.ToR1CS()
	addEntry("expo", r1cs, good, bad)
}
