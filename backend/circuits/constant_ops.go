package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("init constant_ops")
	circuit := frontend.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	elmts := make([]big.Int, 3)
	for i := 0; i < 3; i++ {
		elmts[i].SetUint64(uint64(i) + 10)
	}
	c := circuit.ADD(x, elmts[0])
	c = circuit.MUL(c, elmts[1])
	c = circuit.SUB(c, elmts[2])
	circuit.MUSTBE_EQ(c, y)

	good := make(map[string]interface{})
	good["x"] = 12
	good["y"] = 230

	bad := make(map[string]interface{})
	bad["x"] = 12
	bad["y"] = 228

	r1cs := circuit.ToR1CS()

	addEntry("constant_ops", r1cs, good, bad)
}
