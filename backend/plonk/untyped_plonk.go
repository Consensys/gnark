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
	"io"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gurvy"
)

// UntypedPlonkCS represents a Plonk like circuit
// WIP does not contain logs for the moment
type UntypedPlonkCS struct {

	// Variables
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// Constraints
	Constraints []backend.PlonkConstraint // list of Plonk constraints that yield an output (for example v3 == v1 * v2, return v3)
	Assertions  []backend.PlonkConstraint // list of Plonk constraints that yield no output (for example ensuring v1 == v2)

	// Coefficients in the constraints
	Coeffs    []big.Int      // list of unique coefficients.
	CoeffsIDs map[string]int // map to fast check existence of a coefficient (key = coeff.Text(16))
}

// GetNbConstraints returns the number of constraints
func (upcs *UntypedPlonkCS) GetNbConstraints() uint64 {
	res := uint64(len(upcs.Constraints))
	return res
}

// GetNbWires returns the number of wires (internal)
func (upcs *UntypedPlonkCS) GetNbWires() uint64 {
	res := uint64(upcs.NbInternalVariables)
	return res
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (upcs *UntypedPlonkCS) GetNbCoefficients() int {
	res := len(upcs.Coeffs)
	return res
}

// WriteTo panics (can't serialize untyped R1CS)
func (upcs *UntypedPlonkCS) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented: can't serialize untyped Plonk CS")
}

// GetCurveID returns gurvy.UNKNOWN as this is a untyped R1CS using big.Int
func (upcs *UntypedPlonkCS) GetCurveID() gurvy.ID {
	return gurvy.UNKNOWN
}

// ReadFrom panics (can't deserialize untyped R1CS)
func (upcs *UntypedPlonkCS) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented: can't deserialize untyped R1CS")
}
