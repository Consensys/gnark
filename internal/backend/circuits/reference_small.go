package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func init() {
	const nbConstraints = 5
	circuit := frontend.NewConstraintSystem()

	// declare inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	for i := 0; i < nbConstraints; i++ {
		x = circuit.MUL(x, x)
	}
	circuit.MUSTBE_EQ(x, y)

	good := make(map[string]interface{})
	good["x"] = 2

	// compute expected Y
	var expectedY big.Int
	expectedY.SetUint64(2)

	for i := 0; i < nbConstraints; i++ {
		expectedY.Mul(&expectedY, &expectedY)
	}

	good["y"] = expectedY

	bad := make(map[string]interface{})
	bad["x"] = 2
	bad["y"] = 0

	r1cs := circuit.ToR1CS()

	addEntry("reference_small", r1cs, good, bad)
}
