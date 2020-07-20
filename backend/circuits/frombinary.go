package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init from binary")
	circuit := frontend.NewConstraintSystem()

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

	good := make(map[string]interface{})
	good["b0"] = 1
	good["b1"] = 0
	good["b2"] = 1
	good["b3"] = 1
	good["y"] = 13

	bad := make(map[string]interface{})
	bad["b0"] = 1
	bad["b1"] = 0
	bad["b2"] = 1
	bad["b3"] = 1

	bad["y"] = 12
	r1cs := circuit.ToR1CS()
	addEntry("frombinary", r1cs, good, bad)
}
