package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

func init() {
	var circuit, good, bad xorCircuit
	r1cs, err := frontend.Compile(gurvy.UNKNOWN, &circuit)
	if err != nil {
		panic(err)
	}

	good.B0.Assign(1)
	good.B1.Assign(0)
	good.Y0.Assign(1)

	bad.B0.Assign(1)
	bad.B1.Assign(0)
	bad.Y0.Assign(0)

	addEntry("xor10", r1cs, &good, &bad)
}
