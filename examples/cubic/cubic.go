package main

import (
	"github.com/consensys/gnark/encoding/gob"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

func main() {
	circuit := New()
	gob.Write("circuit.r1cs", circuit, gurvy.BN256)
}

// New return the circuit implementing
//  x**3 + x + 5 == y
func New() *frontend.R1CS {
	// create root constraint system
	circuit := frontend.New()

	// declare secret and public inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	// specify constraints
	x3 := circuit.MUL(x, x, x)
	x3.Tag("x^3") // we can tag a variable for testing and / or debugging purposes, it has no impact on performances
	circuit.MUSTBE_EQ(y, circuit.ADD(x3, x, 5))

	r1cs := circuit.ToR1CS()
	return r1cs
}
