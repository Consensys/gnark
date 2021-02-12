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

package compiled

import (
	"io"
	"math/big"

	"github.com/consensys/gurvy"
)

// SparseR1CS represents a Plonk like circuit
type SparseR1CS struct {

	// Variables
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// Constraints
	Constraints []SparseR1C // list of Plonk constraints that yield an output (for example v3 == v1 * v2, return v3)
	Assertions  []SparseR1C // list of Plonk constraints that yield no output (for example ensuring v1 == v2)

	// Logs (e.g. variables that have been printed using cs.Println)
	Logs []LogEntry

	// Coefficients in the constraints
	Coeffs    []big.Int      // list of unique coefficients.
	CoeffsIDs map[string]int // map to fast check existence of a coefficient (key = coeff.Text(16))
}

// GetNbVariables return number of internal, secret and public variables
func (cs *SparseR1CS) GetNbVariables() (internal, secret, public int) {
	internal = cs.NbInternalVariables
	secret = cs.NbSecretVariables
	public = cs.NbPublicVariables
	return
}

// GetNbConstraints returns the number of constraints
func (cs *SparseR1CS) GetNbConstraints() int {
	return len(cs.Constraints)
}

// GetNbWires returns the number of wires (internal)
func (cs *SparseR1CS) GetNbWires() int {
	return cs.NbInternalVariables
}

// FrSize panics
func (cs *SparseR1CS) FrSize() int {
	panic("not implemented")
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (cs *SparseR1CS) GetNbCoefficients() int {
	res := len(cs.Coeffs)
	return res
}

// CurveID returns gurvy.UNKNOWN as this is a untyped R1CS using big.Int
func (cs *SparseR1CS) CurveID() gurvy.ID {
	return gurvy.UNKNOWN
}

// WriteTo panics (can't serialize untyped R1CS)
func (cs *SparseR1CS) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented: can't serialize untyped Plonk CS")
}

// ReadFrom panics (can't deserialize untyped R1CS)
func (cs *SparseR1CS) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented: can't deserialize untyped R1CS")
}
