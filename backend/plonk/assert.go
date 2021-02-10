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
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256/cs"
	witness_bn256 "github.com/consensys/gnark/internal/backend/bn256/witness"

	backend_bls381 "github.com/consensys/gnark/internal/backend/bls381/cs"
	witness_bls381 "github.com/consensys/gnark/internal/backend/bls381/witness"

	backend_bls377 "github.com/consensys/gnark/internal/backend/bls377/cs"
	witness_bls377 "github.com/consensys/gnark/internal/backend/bls377/witness"

	backend_bw761 "github.com/consensys/gnark/internal/backend/bw761/cs"
	witness_bw761 "github.com/consensys/gnark/internal/backend/bw761/witness"

	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

// Assert is a helper to test circuits
type Assert struct {
	*require.Assertions
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

// SolvingSucceeded Verifies that the pcs.PCS is solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingSucceeded(pcs backend.ConstraintSystem, witness frontend.Witness) {
	assert.NoError(solvePlonkSystem(pcs, witness))
}

// SolvingFailed Verifies that the pcs.PCS is not solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingFailed(pcs backend.ConstraintSystem, witness frontend.Witness) {
	assert.Error(solvePlonkSystem(pcs, witness))
}

func solvePlonkSystem(pcs backend.ConstraintSystem, witness frontend.Witness) error {
	switch _pcs := pcs.(type) {
	case *backend_bn256.SparseR1CS:
		w, err := witness_bn256.Full(witness, true)
		if err != nil {
			return err
		}
		return _pcs.IsSolved(w)
	case *backend_bls381.SparseR1CS:
		w, err := witness_bls381.Full(witness, true)
		if err != nil {
			return err
		}
		return _pcs.IsSolved(w)
	case *backend_bls377.SparseR1CS:
		w, err := witness_bls377.Full(witness, true)
		if err != nil {
			return err
		}
		return _pcs.IsSolved(w)
	case *backend_bw761.SparseR1CS:
		w, err := witness_bw761.Full(witness, true)
		if err != nil {
			return err
		}
		return _pcs.IsSolved(w)
	default:
		panic("WIP")
	}
}
