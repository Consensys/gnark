package server

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

const (
	pkExt      = ".pk"
	vkExt      = ".vk"
	kzgExt     = ".kzg"
	circuitExt = ".ccs"
)

type circuit struct {
	backendID         backend.ID
	curveID           ecc.ID
	ccs               frontend.CompiledConstraintSystem
	fullWitnessSize   int
	publicWitnessSize int

	// groth16 precompute
	groth16 struct {
		pk groth16.ProvingKey
		vk groth16.VerifyingKey
	}

	// plonk precompute
	plonk struct {
		pk     plonk.ProvingKey
		kzgSRS kzg.SRS
	}
}
