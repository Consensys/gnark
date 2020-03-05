package main

import (
	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/std/gadget/hash/mimc"
)

func main() {
	circuit := New()
	circuit.Write("circuit.r1cs")
}

// New return the circuit implementing
//  a pre image check
func New() cs.CS {
	// create root constraint system
	circuit := cs.New()

	// declare secret and public inputs
	pi := circuit.SECRET_INPUT("pi")
	h := circuit.PUBLIC_INPUT("h")

	// specify constraints
	mimc := mimc.NewMiMC("seed")

	circuit.MUSTBE_EQ(pi, mimc.Hash(&circuit, h))

	return circuit
}
