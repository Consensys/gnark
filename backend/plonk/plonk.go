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

	bls377witness "github.com/consensys/gnark/internal/backend/bls377/witness"
	bls381witness "github.com/consensys/gnark/internal/backend/bls381/witness"
	bn256witness "github.com/consensys/gnark/internal/backend/bn256/witness"
	bw761witness "github.com/consensys/gnark/internal/backend/bw761/witness"

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
func Setup(spr frontend.CompiledConstraintSystem, polynomialCommitment polynomial.CommitmentScheme, publicWitness frontend.Circuit) PublicData {

	switch _spr := spr.(type) {
	case *backend_bn256.SparseR1CS:
		wPublic := bn256witness.Witness{}
		wPublic.FromPublicAssignment(publicWitness)
		publicData := plonkbn256.SetupRaw(_spr, polynomialCommitment, wPublic)
		return &publicData

	case *backend_bls381.SparseR1CS:
		wPublic := bls381witness.Witness{}
		wPublic.FromPublicAssignment(publicWitness)
		publicData := plonkbls381.SetupRaw(_spr, polynomialCommitment, wPublic)
		return &publicData

	case *backend_bls377.SparseR1CS:
		wPublic := bls377witness.Witness{}
		wPublic.FromPublicAssignment(publicWitness)
		publicData := plonkbls377.SetupRaw(_spr, polynomialCommitment, wPublic)
		return &publicData

	case *backend_bw761.SparseR1CS:
		wPublic := bw761witness.Witness{}
		wPublic.FromPublicAssignment(publicWitness)
		publicData := plonkbw761.SetupRaw(_spr, polynomialCommitment, wPublic)
		return &publicData

	default:
		panic("unrecognized R1CS curve type")
	}

}

// Prove generates plonk proof from a circuit, associated preprocessed public data, and the witness
func Prove(spr frontend.CompiledConstraintSystem, publicData PublicData, witness frontend.Circuit) Proof {

	switch _spr := spr.(type) {
	case *backend_bn256.SparseR1CS:
		wFull := bn256witness.Witness{}
		wFull.FromFullAssignment(witness)
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbn256.PublicRaw)
		proof := plonkbn256.ProveRaw(_spr, _publicData, wFull)
		return &proof

	case *backend_bls381.SparseR1CS:
		wFull := bls381witness.Witness{}
		wFull.FromFullAssignment(witness)
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbls381.PublicRaw)
		proof := plonkbls381.ProveRaw(_spr, _publicData, wFull)
		return &proof

	case *backend_bls377.SparseR1CS:
		wFull := bls377witness.Witness{}
		wFull.FromFullAssignment(witness)
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbls377.PublicRaw)
		proof := plonkbls377.ProveRaw(_spr, _publicData, wFull)
		return &proof

	case *backend_bw761.SparseR1CS:
		wFull := bw761witness.Witness{}
		wFull.FromFullAssignment(witness)
		// TODO public data may not always be of type Raw
		_publicData := publicData.(*plonkbw761.PublicRaw)
		proof := plonkbw761.ProveRaw(_spr, _publicData, wFull)
		return &proof

	default:
		panic("unrecognized R1CS curve type")
	}
}

// Verify verifies a plonk proof, from the proof, preprocessed public data, and public witness.
func Verify(proof Proof, publicData PublicData, publicWitness frontend.Circuit) bool {

	switch _proof := proof.(type) {

	case *plonkbn256.ProofRaw:
		_publicData := publicData.(*plonkbn256.PublicRaw)
		_publicWitness := bn256witness.Witness{}
		_publicWitness.FromPublicAssignment(publicWitness)
		return plonkbn256.VerifyRaw(_proof, _publicData, _publicWitness)

	case *plonkbls381.ProofRaw:
		_publicData := publicData.(*plonkbls381.PublicRaw)
		_publicWitness := bls381witness.Witness{}
		_publicWitness.FromPublicAssignment(publicWitness)
		return plonkbls381.VerifyRaw(_proof, _publicData, _publicWitness)

	case *plonkbls377.ProofRaw:
		_publicData := publicData.(*plonkbls377.PublicRaw)
		_publicWitness := bls377witness.Witness{}
		_publicWitness.FromPublicAssignment(publicWitness)
		return plonkbls377.VerifyRaw(_proof, _publicData, _publicWitness)

	case *plonkbw761.ProofRaw:
		_publicData := publicData.(*plonkbw761.PublicRaw)
		_publicWitness := bw761witness.Witness{}
		_publicWitness.FromPublicAssignment(publicWitness)
		return plonkbw761.VerifyRaw(_proof, _publicData, _publicWitness)

	default:
		panic("unrecognized proof type")
	}
}
