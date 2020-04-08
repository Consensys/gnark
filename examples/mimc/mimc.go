package main

import (
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
)

func main() {
	circuit := New()
	circuit.Write("circuit.r1cs")
}

// New return the circuit implementing
// a pre image check
func New() *backend_bn256.R1CS {
	// create root constraint system
	circuit := frontend.New()

	// declare secret and public inputs
	preImage := circuit.SECRET_INPUT("pi")
	hash := circuit.PUBLIC_INPUT("h")

	// hash function
	mimc, _ := mimc.NewMiMC("seed", gurvy.BN256)

	// specify constraints
	// mimc(preImage) == hash
	circuit.MUSTBE_EQ(hash, mimc.Hash(&circuit, preImage))

	_r1cs := circuit.ToR1CS()
	r1cs := backend_bn256.New(_r1cs)

	return &r1cs
}
