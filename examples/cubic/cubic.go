package main

import "github.com/consensys/gnark/cs"

func main() {
	circuit := New()
	circuit.Write("circuit.r1cs")
}

// New return the circuit implementing
//  x**3 + x + 5 == y
func New() cs.CS {
	// create root constraint system
	circuit := cs.New()

	// declare secret and public inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	// specify constraints
	x3 := circuit.MUL(x, x, x)
	x3.Tag("x^3") // we can tag a variable for testing and / or debugging purposes, it has no impact on performances
	circuit.MUSTBE_EQ(y, circuit.ADD(x3, x, 5))

	return circuit
}
