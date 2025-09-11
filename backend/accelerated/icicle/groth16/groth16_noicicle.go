//go:build !icicle

package groth16

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func Prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (groth16.Proof, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

func Setup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

func DummySetup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

func NewProvingKey(curveID ecc.ID) groth16.ProvingKey {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}
