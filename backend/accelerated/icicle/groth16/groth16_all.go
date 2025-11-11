// Package groth16 implements Groth16 proof system with ICICLE acceleration.
package groth16

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Verify verifies Groth16 proof. It wraps [groth16.Verify] function, but is provided for completeness.
func Verify(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness, opts ...backend.VerifierOption) error {
	return groth16.Verify(proof, vk, publicWitness, opts...)
}

// NewVerifyingKey creates a new empty verifying key for deserializing into. It is compatible with [groth16.NewVerifyingKey].
func NewVerifyingKey(curveID ecc.ID) groth16.VerifyingKey {
	return groth16.NewVerifyingKey(curveID)
}

// NewProof creates a new empty proof for deserializing into. It is compatible with [groth16.NewProof].
func NewProof(curveID ecc.ID) groth16.Proof {
	return groth16.NewProof(curveID)
}

// NewCS creates new typed R1CS constraint system for the given curve. It is compatible with [groth16.NewCS].
// It is used for deserializing R1CS constraint systems.
func NewCS(curveID ecc.ID) constraint.ConstraintSystem {
	return groth16.NewCS(curveID)
}
