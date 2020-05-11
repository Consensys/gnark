package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init div")
	circuit := frontend.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.SECRET_INPUT("y")
	z := circuit.PUBLIC_INPUT("z")
	m := circuit.MUL(x, x)
	d := circuit.DIV(m, y)
	circuit.MUSTBE_EQ(d, z)

	// expected z
	var expectedZ big.Int
	expectedZ.SetUint64(3)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "x", 6)
	good.Assign(backend.Secret, "y", 12)
	good.Assign(backend.Public, "z", expectedZ)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "x", 4)
	bad.Assign(backend.Secret, "y", 10)
	bad.Assign(backend.Public, "z", 42)

	r1cs := circuit.ToR1CS()
	addEntry("div", r1cs, good, bad)
}
