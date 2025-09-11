package groth16

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func Verify(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness, opts ...backend.VerifierOption) error {
	return groth16.Verify(proof, vk, publicWitness, opts...)
}

func NewVerifyingKey(curveID ecc.ID) groth16.VerifyingKey {
	return groth16.NewVerifyingKey(curveID)
}

func NewProof(curveID ecc.ID) groth16.Proof {
	return groth16.NewProof(curveID)
}

func NewCS(curveID ecc.ID) constraint.ConstraintSystem {
	return groth16.NewCS(curveID)
}
