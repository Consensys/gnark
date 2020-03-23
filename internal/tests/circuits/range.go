package circuits

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

func init() {
	circuit := frontend.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	c1 := circuit.MUL(x, y)
	c2 := circuit.MUL(c1, y)

	circuit.MUSTBE_LESS_OR_EQ(c2, 161)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "x", 10)
	good.Assign(backend.Public, "y", 4)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "x", 10)
	bad.Assign(backend.Public, "y", 5)

	r1cs := circuit.ToR1CS()
	addEntry("range", r1cs, good, bad)
}
