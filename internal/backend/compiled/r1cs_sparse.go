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

	"github.com/consensys/gnark-crypto/ecc"
)

// SparseR1CS represents a Plonk like circuit
type SparseR1CS struct {

	// Variables [publicVariables| secretVariables | internalVariables ]
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// Constraints
	Constraints []SparseR1C // list of PLONK constraints that yield an output (for example v3 == v1 * v2, return v3)
	Assertions  []SparseR1C // list of PLONK constraints that yield no output (for example ensuring v1 == v2)

	// Logs (e.g. variables that have been printed using cs.Println)
	Logs []LogEntry
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
	return len(cs.Constraints) + len(cs.Assertions)
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
	panic("not implemented")
}

// CurveID returns ecc.UNKNOWN as this is a untyped R1CS using big.Int
func (cs *SparseR1CS) CurveID() ecc.ID {
	return ecc.UNKNOWN
}

// WriteTo panics
func (cs *SparseR1CS) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented")
}

// ReadFrom panics
func (cs *SparseR1CS) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented")
}

// SetLoggerOutput replace existing logger output with provided one
// default uses os.Stdout
// if nil is provided, logs are not printed
func (cs *SparseR1CS) SetLoggerOutput(w io.Writer) {
	panic("not implemented")
}
