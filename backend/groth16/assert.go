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

package groth16

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	backend_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	backend_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	backend_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	backend_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	backend_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/cs"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
)

// IsSolved attempts to solve the constraint system with provided witness
// returns nil if it succeeds, error otherwise.
func IsSolved(r1cs frontend.CompiledConstraintSystem, witness frontend.Circuit, opts ...func(opt *backend.ProverOption) error) error {

	// apply options
	opt, err := backend.NewProverOption(opts...)
	if err != nil {
		return err
	}

	switch _r1cs := r1cs.(type) {
	case *backend_bls12377.R1CS:
		w := witness_bls12377.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w, opt)
	case *backend_bls12381.R1CS:
		w := witness_bls12381.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w, opt)
	case *backend_bn254.R1CS:
		w := witness_bn254.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w, opt)
	case *backend_bw6761.R1CS:
		w := witness_bw6761.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w, opt)
	case *backend_bls24315.R1CS:
		w := witness_bls24315.Witness{}
		if err := w.FromFullAssignment(witness); err != nil {
			return err
		}
		return _r1cs.IsSolved(w, opt)
	default:
		panic("unrecognized R1CS curve type")
	}
}
