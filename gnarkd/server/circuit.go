package server

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

const (
	pkExt   = ".pk"
	vkExt   = ".vk"
	r1csExt = ".r1cs"
)

type circuit struct {
	pk   groth16.ProvingKey
	vk   groth16.VerifyingKey
	r1cs frontend.CompiledConstraintSystem
}
