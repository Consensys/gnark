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

	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256/pcs"
	witness_bn256 "github.com/consensys/gnark/internal/backend/bn256/witness"

	"github.com/consensys/gnark/backend/pcs"
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
func (assert *Assert) SolvingSucceeded(pcs pcs.CS, witness frontend.Witness) {
	assert.NoError(solvePlonkSystem(pcs, witness))
	// ----- to delete -----
	// err := solvePlonkSystem(pcs, witness)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// ---------------------
}

// SolvingFailed Verifies that the pcs.PCS is not solved with the given witness, without executing plonk workflow
func (assert *Assert) SolvingFailed(pcs pcs.CS, witness frontend.Witness) {
	assert.Error(solvePlonkSystem(pcs, witness))
}

func solvePlonkSystem(pcs pcs.CS, witness frontend.Witness) error {
	switch _pcs := pcs.(type) {
	case *backend_bn256.CS:
		w, err := witness_bn256.Full(witness)
		if err != nil {
			return err
		}
		return _pcs.IsSolved(w)
	default:
		panic("WIP")
	}
}
