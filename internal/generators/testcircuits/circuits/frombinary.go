package circuits

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

func init() {
	circuit := frontend.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")
	b2 := circuit.SECRET_INPUT("b2")
	b3 := circuit.SECRET_INPUT("b3")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)
	circuit.MUSTBE_BOOLEAN(b2)
	circuit.MUSTBE_BOOLEAN(b3)

	y := circuit.PUBLIC_INPUT("y")

	r := circuit.FROM_BINARY(b0, b1, b2, b3)

	circuit.MUSTBE_EQ(y, r)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "b0", 1)
	good.Assign(backend.Secret, "b1", 0)
	good.Assign(backend.Secret, "b2", 1)
	good.Assign(backend.Secret, "b3", 1)
	good.Assign(backend.Public, "y", 13)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "b0", 1)
	bad.Assign(backend.Secret, "b1", 0)
	bad.Assign(backend.Secret, "b2", 1)
	bad.Assign(backend.Secret, "b3", 1)
	bad.Assign(backend.Public, "y", 12)

	r1cs := circuit.ToR1CS()
	addEntry("frombinary", r1cs, good, bad)
}
