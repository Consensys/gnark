package main

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/std/gadget/hash/mimc"
)

func main() {
	circuit := New()
	circuit.Write("circuit.r1cs")
}

// New return the circuit implementing
// a pre image check
func New() *backend.R1CS {
	// create root constraint system
	circuit := frontend.New()

	// declare secret and public inputs
	preImage := circuit.SECRET_INPUT("pi")
	hash := circuit.PUBLIC_INPUT("h")

	// hash function
	mimc := mimc.NewMiMC("seed")

	// specify constraints
	// mimc(preImage) == hash
	circuit.MUSTBE_EQ(hash, mimc.Hash(&circuit, preImage))

	return circuit.ToR1CS()
}
