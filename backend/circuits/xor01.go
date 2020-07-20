package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init xor01")
	circuit := frontend.NewConstraintSystem()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	y0 := circuit.PUBLIC_INPUT("y0")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	z0 := circuit.XOR(b0, b1)

	circuit.MUSTBE_EQ(z0, y0)

	good := make(map[string]interface{})
	good["b0"] = 0
	good["b1"] = 1
	good["y0"] = 1

	bad := make(map[string]interface{})
	bad["b0"] = 0
	bad["b1"] = 1
	bad["y0"] = 0

	r1cs := circuit.ToR1CS()
	addEntry("xor01", r1cs, good, bad)
}
