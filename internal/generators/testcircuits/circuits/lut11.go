package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init lut11")
	circuit := frontend.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	z := circuit.PUBLIC_INPUT("z")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	var lookuptable [4]big.Int

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := circuit.SELECT_LUT(b1, b0, lookuptable)

	circuit.MUSTBE_EQ(r, z)

	good := make(map[string]interface{})
	good["b0"] = 1
	good["b1"] = 1
	good["z"] = 7

	bad := make(map[string]interface{})
	bad["b0"] = 1
	bad["b1"] = 1
	bad["z"] = 9

	r1cs := circuit.ToR1CS()
	addEntry("lut11", r1cs, good, bad)
}
