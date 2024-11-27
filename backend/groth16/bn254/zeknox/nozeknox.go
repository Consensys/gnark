//go:build !zeknox

package zeknox_bn254

import (
	"fmt"

	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
)

type ProvingKey struct {
	groth16_bn254.ProvingKey
}

const HasZeknox = false

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	return nil, fmt.Errorf("zeknox backend requested but program compiled without 'zeknox' build tag")
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bn254.VerifyingKey) error {
	return groth16_bn254.Setup(r1cs, &pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bn254.DummySetup(r1cs, &pk.ProvingKey)
}

func (pk *ProvingKey) Free() {
}
