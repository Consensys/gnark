package main

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve/fr"
	"github.com/consensys/gnark/frontend"
)

func init() {
	circuit := frontend.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	z := circuit.PUBLIC_INPUT("z")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	var lookuptable [4]fr.Element

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := circuit.SELECT_LUT(b1, b0, lookuptable)

	circuit.MUSTBE_EQ(r, z)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "b0", 0)
	good.Assign(backend.Secret, "b1", 1)
	good.Assign(backend.Public, "z", 22)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "b0", 0)
	bad.Assign(backend.Secret, "b1", 1)
	bad.Assign(backend.Public, "z", 11)

	r1cs := circuit.ToR1CS()
	addEntry("lut10", r1cs, good, bad)
}
