//go:build !icicle

package icicle_bn254

import (
	"fmt"

	"github.com/irfanbozkurt/gnark/backend"
	groth16_bn254 "github.com/irfanbozkurt/gnark/backend/groth16/bn254"
	"github.com/irfanbozkurt/gnark/backend/witness"
	cs "github.com/irfanbozkurt/gnark/constraint/bn254"
)

const HasIcicle = false

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	return nil, fmt.Errorf("icicle backend requested but program compiled without 'icicle' build tag")
}
