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
// a pre image check
func New() cs.CS {
	// create root constraint system
	circuit := cs.New()

	// declare secret and public inputs
	preImage := circuit.SECRET_INPUT("pi")
	hash := circuit.PUBLIC_INPUT("h")

	// hash function
	mimc := mimc.NewMiMC("seed")

	// specify constraints
	// mimc(preImage) == hash
	circuit.MUSTBE_EQ(hash, mimc.Hash(&circuit, preImage))

	return circuit
}
