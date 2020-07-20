package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init div")
	circuit := frontend.NewConstraintSystem()

	x := circuit.SECRET_INPUT("x")
	y := circuit.SECRET_INPUT("y")
	z := circuit.PUBLIC_INPUT("z")
	m := circuit.MUL(x, x)
	d := circuit.DIV(m, y)
	circuit.MUSTBE_EQ(d, z)

	// expected z
	var expectedZ big.Int
	expectedZ.SetUint64(3)

	good := make(map[string]interface{})
	good["x"] = 6
	good["y"] = 12
	good["z"] = expectedZ

	bad := make(map[string]interface{})
	bad["x"] = 4
	bad["y"] = 10
	bad["z"] = 42

	r1cs := circuit.ToR1CS()
	addEntry("div", r1cs, good, bad)
}
