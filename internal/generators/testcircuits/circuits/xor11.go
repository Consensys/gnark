package circuits

import (
	"fmt"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init xor11")
	circuit := frontend.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	y0 := circuit.PUBLIC_INPUT("y0")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	z0 := circuit.XOR(b0, b1)

	circuit.MUSTBE_EQ(z0, y0)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "b0", 1)
	good.Assign(backend.Secret, "b1", 1)
	good.Assign(backend.Public, "y0", 0)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "b0", 1)
	bad.Assign(backend.Secret, "b1", 1)
	bad.Assign(backend.Public, "y0", 1)

	r1cs := circuit.ToR1CS()
	addEntry("xor11", r1cs, good, bad)
}
