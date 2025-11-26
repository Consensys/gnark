//go:build !icicle

package groth16

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
//
// NB! the provided proving key must contain the device pointers required for
// the acceleration. Initialize and deserialize the proving key using
// [NewProvingKey] and the serialization methods.
func Prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, fullWitness witness.Witness, opts ...icicle.Option) (groth16.Proof, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

// Setup generates a proving and verifying key for a given r1cs.
//
// The method wraps the [groth16.Setup] method, but the returned proving key
// contains device pointers for acceleration. To convert the key to a standard
// Groth16 proving key, use the serialization methods.
func Setup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

// DummySetup generates a dummy proving key for a given circuit. It doesn't perform
// the precomputations and thus the returned proving key cannot be used to generate
// proofs. The method is useful for development and testing purposes.
//
// The method wraps the [groth16.DummySetup] method, but the returned proving key
// contains device pointers for acceleration. To convert the key to a standard
// Groth16 proving key, use the serialization methods.
func DummySetup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

// NewProvingKey creates a new empty proving key for deserializing into.
//
// The method is compatible with [groth16.NewProvingKey], but returns an
// ICICLE proving key with device pointers for acceleration.
func NewProvingKey(curveID ecc.ID) groth16.ProvingKey {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}
