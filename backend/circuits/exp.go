package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init exp")
	circuit := frontend.NewConstraintSystem()

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

	good := make(map[string]interface{})
	good["x"] = 2
	good["e"] = 12
	good["y"] = 4096

	bad := make(map[string]interface{})
	bad["x"] = 2
	bad["e"] = 12
	bad["y"] = 4095

	r1cs := circuit.ToR1CS()
	addEntry("expo", r1cs, good, bad)
}
