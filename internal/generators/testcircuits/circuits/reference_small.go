package circuits

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve/fr"
	"github.com/consensys/gnark/frontend"
)

func init() {
	const nbConstraints = 60
	circuit := frontend.New()

	// declare inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	for i := 0; i < nbConstraints; i++ {
		x = circuit.MUL(x, x)
	}
	circuit.MUSTBE_EQ(x, y)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "x", 2)

	// compute expected Y
	expectedY := fr.Element{}
	expectedY.SetUint64(2)

	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}

	good.Assign(backend.Public, "y", expectedY)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "x", 2)
	bad.Assign(backend.Public, "y", 0)

	r1cs := circuit.ToR1CS()

	addEntry("reference_small", r1cs, good, bad)
}
