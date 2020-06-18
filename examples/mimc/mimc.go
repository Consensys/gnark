package main

import (
	"github.com/consensys/gnark/encoding/gob"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
)

func main() {
	circuit := New()
	gob.Write("circuit.r1cs", circuit, gurvy.BN256)
}

// New return the circuit implementing
// a pre image check
func New() *frontend.R1CS {
	// create root constraint system
	circuit := frontend.New()

	// declare secret and public inputs
	preImage := circuit.SECRET_INPUT("pi")
	hash := circuit.PUBLIC_INPUT("h")

	// hash function
	mimc, _ := mimc.NewMiMCGadget("seed", gurvy.BN256)

	// specify constraints
	// mimc(preImage) == hash
	circuit.MUSTBE_EQ(hash, mimc.Hash(&circuit, preImage))

	r1cs := circuit.ToR1CS()

	return r1cs
}
