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

package plonk

import (
	"github.com/consensys/gnark/crypto/polynomial"
	"github.com/consensys/gnark/frontend"

	backend_bls377 "github.com/consensys/gnark/internal/backend/bls377/cs"
	backend_bls381 "github.com/consensys/gnark/internal/backend/bls381/cs"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256/cs"
	backend_bw761 "github.com/consensys/gnark/internal/backend/bw761/cs"

	plonkbls377 "github.com/consensys/gnark/internal/backend/bls377/plonk"
	plonkbls381 "github.com/consensys/gnark/internal/backend/bls381/plonk"
	plonkbn256 "github.com/consensys/gnark/internal/backend/bn256/plonk"
	plonkbw761 "github.com/consensys/gnark/internal/backend/bw761/plonk"
)

// PublicData contains
// * polynomials corresponding to the coefficients ql,qr,qm,qo,qk (either raw or committed)
// * polynomials corresponding to the permutations s1,s2,s3 (either raw or committed)
// * the commitment scheme
// * the fft domains
type PublicData interface{}

// Proof contains a plonk proof. The content of the proof might vary according
// to the plonk version which is chosen.
// For instance it can be the commitments of L,R,O,H,Z and the opening proofs.
type Proof interface{}

// Setup prepares the public data associated to a circuit + public inputs.
func Setup(sparseR1cs frontend.CompiledConstraintSystem, polynomialCommitment polynomial.CommitmentScheme, publicWitness frontend.Circuit) PublicData {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn256.SparseR1CS:
		publicData := plonkbn256.SetupRaw(_sparseR1cs, polynomialCommitment, publicWitness)
		return publicData

	case *backend_bls381.SparseR1CS:
		publicData := plonkbls381.SetupRaw(_sparseR1cs, polynomialCommitment, publicWitness)
		return publicData

	case *backend_bls377.SparseR1CS:
		publicData := plonkbls377.SetupRaw(_sparseR1cs, polynomialCommitment, publicWitness)
		return publicData

	case *backend_bw761.SparseR1CS:
		publicData := plonkbw761.SetupRaw(_sparseR1cs, polynomialCommitment, publicWitness)
		return publicData

	default:
		panic("unrecognized R1CS curve type")
	}

}

// Prove generates plonk proof from a circuit, associated preprocessed public data, and the witness
func Prove(sparseR1cs frontend.CompiledConstraintSystem, publicData PublicData, witnessFull frontend.Circuit) Proof {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn256.SparseR1CS:
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbn256.PublicRaw)
		proof := plonkbn256.ProveRaw(_sparseR1cs, _publicData, witnessFull)
		return proof

	case *backend_bls381.SparseR1CS:
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbls381.PublicRaw)
		proof := plonkbls381.ProveRaw(_sparseR1cs, _publicData, witnessFull)
		return proof

	case *backend_bls377.SparseR1CS:
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbls377.PublicRaw)
		proof := plonkbls377.ProveRaw(_sparseR1cs, _publicData, witnessFull)
		return proof

	case *backend_bw761.SparseR1CS:
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbw761.PublicRaw)
		proof := plonkbw761.ProveRaw(_sparseR1cs, _publicData, witnessFull)
		return proof

	default:
		panic("unrecognized R1CS curve type")
	}
}

// Verify verifies a plonk proof, from the proof, preprocessed public data, and public witness.
func Verify(proof Proof, publicData PublicData, publicWitness frontend.Circuit) bool {

	switch _proof := proof.(type) {

	case *plonkbn256.ProofRaw:
		_publicData := publicData.(*plonkbn256.PublicRaw)
		return plonkbn256.VerifyRaw(_proof, _publicData, publicWitness)

	case *plonkbls381.ProofRaw:
		_publicData := publicData.(*plonkbls381.PublicRaw)
		return plonkbls381.VerifyRaw(_proof, _publicData, publicWitness)

	case *plonkbls377.ProofRaw:
		_publicData := publicData.(*plonkbls377.PublicRaw)
		return plonkbls377.VerifyRaw(_proof, _publicData, publicWitness)

	case *plonkbw761.ProofRaw:
		_publicData := publicData.(*plonkbw761.PublicRaw)
		return plonkbw761.VerifyRaw(_proof, _publicData, publicWitness)

	default:
		panic("unrecognized proof type")
	}
}
