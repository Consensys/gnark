package main

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve/fr"
	"github.com/consensys/gnark/frontend"
)

func init() {
	circuit := frontend.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	elmts := make([]fr.Element, 3)
	for i := 0; i < 3; i++ {
		elmts[i].SetUint64(uint64(i) + 10)
	}
	c := circuit.ADD(x, elmts[0])
	c = circuit.MUL(c, elmts[1])
	c = circuit.SUB(c, elmts[2])
	circuit.MUSTBE_EQ(c, y)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "x", 12)
	good.Assign(backend.Public, "y", 230)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "x", 12)
	bad.Assign(backend.Public, "y", 228)

	r1cs := circuit.ToR1CS()

	addEntry("constant_ops", r1cs, good, bad)
}
