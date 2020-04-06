package main

import (
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/frontend"
)

func main() {
	circuit := New()
	circuit.Write("circuit.r1cs")
}

// New return the circuit implementing
//  x**3 + x + 5 == y
func New() *backend_bn256.R1CS {
	// create root constraint system
	circuit := frontend.New()

	// declare secret and public inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	// specify constraints
	x3 := circuit.MUL(x, x, x)
	x3.Tag("x^3") // we can tag a variable for testing and / or debugging purposes, it has no impact on performances
	circuit.MUSTBE_EQ(y, circuit.ADD(x3, x, 5))

	_r1cs := circuit.ToR1CS()

	r1cs := backend_bn256.New(_r1cs)
	return &r1cs
}
