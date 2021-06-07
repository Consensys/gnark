// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package plonk implements PLONK Zero Knowledge Proof system.
//
// See also
//
// https://eprint.iacr.org/2019/953
package plonk

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	mockcommitment_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/polynomial/mockcommitment"
	mockcommitment_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial/mockcommitment"
	mockcommitment_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial/mockcommitment"
	mockcommitment_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/polynomial/mockcommitment"
	"github.com/consensys/gnark-crypto/polynomial"
	"github.com/consensys/gnark/frontend"

	backend_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	backend_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	backend_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	backend_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"

	plonkbls12377 "github.com/consensys/gnark/internal/backend/bls12-377/plonk"
	plonkbls12381 "github.com/consensys/gnark/internal/backend/bls12-381/plonk"
	plonkbn254 "github.com/consensys/gnark/internal/backend/bn254/plonk"
	plonkbw6761 "github.com/consensys/gnark/internal/backend/bw6-761/plonk"

	bls12377witness "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	bls12381witness "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
	bw6761witness "github.com/consensys/gnark/internal/backend/bw6-761/witness"
)

// PublicData contains
//
// 	- polynomials corresponding to the coefficients ql,qr,qm,qo,qk (either raw or committed)
// 	- polynomials corresponding to the permutations s1,s2,s3 (either raw or committed)
// 	- the commitment scheme
// 	- the fft domains
type PublicData interface {
	io.WriterTo
	io.ReaderFrom
}

// Proof content might vary according to the PLONK version which is chosen.
//
// For instance it can be the commitments of L,R,O,H,Z and the opening proofs.
type Proof interface{}

// Setup prepares the public data associated to a circuit + public inputs.
func Setup(sparseR1cs frontend.CompiledConstraintSystem, polynomialCommitment polynomial.CommitmentScheme, publicWitness frontend.Circuit) (PublicData, error) {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn254.SparseR1CS:
		w := bn254witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbn254.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls12381.SparseR1CS:
		w := bls12381witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbls12381.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls12377.SparseR1CS:
		w := bls12377witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbls12377.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bw6761.SparseR1CS:
		w := bw6761witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbw6761.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	default:
		panic("unrecognized R1CS curve type")
	}

}

// SetupDummyCommitment is used for testing purposes, it sets up public data with dummy polynomial commitment scheme.
func SetupDummyCommitment(sparseR1cs frontend.CompiledConstraintSystem, publicWitness frontend.Circuit) (PublicData, error) {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn254.SparseR1CS:
		w := bn254witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bn254.Scheme{}
		publicData := plonkbn254.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls12381.SparseR1CS:
		w := bls12381witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bls12381.Scheme{}
		publicData := plonkbls12381.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls12377.SparseR1CS:
		w := bls12377witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bls12377.Scheme{}
		publicData := plonkbls12377.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bw6761.SparseR1CS:
		w := bw6761witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bw6761.Scheme{}
		publicData := plonkbw6761.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	default:
		panic("unrecognized R1CS curve type")
	}

}

// Prove generates PLONK proof from a circuit, associated preprocessed public data, and the witness
func Prove(sparseR1cs frontend.CompiledConstraintSystem, publicData PublicData, fullWitness frontend.Circuit) (Proof, error) {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn254.SparseR1CS:
		_publicData := publicData.(*plonkbn254.PublicRaw)
		w := bn254witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof, err := plonkbn254.ProveRaw(_sparseR1cs, _publicData, w)
		if err != nil {
			return proof, err
		}
		return proof, nil

	case *backend_bls12381.SparseR1CS:
		_publicData := publicData.(*plonkbls12381.PublicRaw)
		w := bls12381witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof, err := plonkbls12381.ProveRaw(_sparseR1cs, _publicData, w)
		if err != nil {
			return proof, err
		}
		return proof, nil

	case *backend_bls12377.SparseR1CS:
		_publicData := publicData.(*plonkbls12377.PublicRaw)
		w := bls12377witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof, err := plonkbls12377.ProveRaw(_sparseR1cs, _publicData, w)
		if err != nil {
			return proof, err
		}
		return proof, nil

	case *backend_bw6761.SparseR1CS:
		_publicData := publicData.(*plonkbw6761.PublicRaw)
		w := bw6761witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof, err := plonkbw6761.ProveRaw(_sparseR1cs, _publicData, w)
		if err != nil {
			return proof, err
		}
		return proof, nil

	default:
		panic("unrecognized R1CS curve type")
	}
}

// Verify verifies a PLONK proof, from the proof, preprocessed public data, and public witness.
func Verify(proof Proof, publicData PublicData, publicWitness frontend.Circuit) error {

	switch _proof := proof.(type) {

	case *plonkbn254.ProofRaw:
		_publicData := publicData.(*plonkbn254.PublicRaw)
		w := bn254witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbn254.VerifyRaw(_proof, _publicData, w)

	case *plonkbls12381.ProofRaw:
		_publicData := publicData.(*plonkbls12381.PublicRaw)
		w := bls12381witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbls12381.VerifyRaw(_proof, _publicData, w)

	case *plonkbls12377.ProofRaw:
		_publicData := publicData.(*plonkbls12377.PublicRaw)
		w := bls12377witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbls12377.VerifyRaw(_proof, _publicData, w)

	case *plonkbw6761.ProofRaw:
		_publicData := publicData.(*plonkbw6761.PublicRaw)
		w := bw6761witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbw6761.VerifyRaw(_proof, _publicData, w)

	default:
		panic("unrecognized proof type")
	}
}

// NewCS instantiate a concrete curved-typed SparseR1CS and return a CompiledConstraintSystem interface
// This method exists for (de)serialization purposes
func NewCS(curveID ecc.ID) frontend.CompiledConstraintSystem {
	var r1cs frontend.CompiledConstraintSystem
	switch curveID {
	case ecc.BN254:
		r1cs = &backend_bn254.SparseR1CS{}
	case ecc.BLS12_377:
		r1cs = &backend_bls12377.SparseR1CS{}
	case ecc.BLS12_381:
		r1cs = &backend_bls12381.SparseR1CS{}
	case ecc.BW6_761:
		r1cs = &backend_bw6761.SparseR1CS{}
	default:
		panic("not implemented")
	}
	return r1cs
}

// NewPublicData instantiates a curve-typed PublicData and returns an interface
// This function exists for serialization purposes
func NewPublicData(curveID ecc.ID) PublicData {
	var data PublicData
	switch curveID {
	case ecc.BN254:
		data = &plonkbn254.PublicRaw{}
	case ecc.BLS12_377:
		data = &plonkbls12377.PublicRaw{}
	case ecc.BLS12_381:
		data = &plonkbls12381.PublicRaw{}
	case ecc.BW6_761:
		data = &plonkbw6761.PublicRaw{}
	default:
		panic("not implemented")
	}

	return data
}
