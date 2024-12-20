//go:build !icicle

package icicle

import (
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
)

const HasIcicle = false

type ProvingKey struct {
	groth16_bn254.ProvingKey
}

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

func NewProvingKey() *ProvingKey {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bn254.VerifyingKey) error {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}
