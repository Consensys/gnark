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
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"

	cs_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	cs_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	cs_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	cs_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	cs_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"

	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"
	"github.com/consensys/gnark-crypto/kzg"
)

// IsSolved attempts to solve the constraint system with provided witness
// returns nil if it succeeds, error otherwise.
func IsSolved(ccs frontend.CompiledConstraintSystem, witness frontend.Circuit, opts ...func(opt *backend.ProverOption) error) error {

	opt, err := backend.NewProverOption(opts...)
	if err != nil {
		return err
	}

	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		w := witness_bn254.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, opt)
	case *cs_bls12381.SparseR1CS:
		w := witness_bls12381.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, opt)
	case *cs_bls12377.SparseR1CS:
		w := witness_bls12377.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, opt)
	case *cs_bw6761.SparseR1CS:
		w := witness_bw6761.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, opt)
	case *cs_bls24315.SparseR1CS:
		w := witness_bls24315.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return tccs.IsSolved(w, opt)
	default:
		panic("unknown constraint system type")
	}
}

func newKZGSrs(ccs frontend.CompiledConstraintSystem) (kzg.SRS, error) {
	fakeRandomness := new(big.Int).SetInt64(42)

	// no randomness in the test SRS
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		size := uint64(len(tccs.Constraints) + tccs.NbPublicVariables)
		return kzg_bn254.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bls12381.SparseR1CS:
		size := uint64(len(tccs.Constraints) + tccs.NbPublicVariables)
		return kzg_bls12381.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bls12377.SparseR1CS:
		size := uint64(len(tccs.Constraints) + tccs.NbPublicVariables)
		return kzg_bls12377.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bw6761.SparseR1CS:
		size := uint64(len(tccs.Constraints) + tccs.NbPublicVariables)
		return kzg_bw6761.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	case *cs_bls24315.SparseR1CS:
		size := uint64(len(tccs.Constraints) + tccs.NbPublicVariables)
		return kzg_bls24315.NewSRS(ecc.NextPowerOfTwo(size)+3, fakeRandomness)
	default:
		panic("unknown constraint system type")
	}
}
