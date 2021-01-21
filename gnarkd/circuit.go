package main

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
)

const (
	pkExt   = ".pk"
	vkExt   = ".vk"
	r1csExt = ".r1cs"
)

type circuit struct {
	pk                groth16.ProvingKey
	vk                groth16.VerifyingKey
	r1cs              r1cs.R1CS
	fullWitnessSize   int
	publicWitnessSize int
}
