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

// R1CS decsribes a set of R1CS constraint
type R1CS struct {
	// Wires
	NbInternalVariables  int
	NbPublicVariables    int // includes ONE wire
	NbSecretVariables    int
	Logs                 []LogEntry
	DebugInfoComputation []LogEntry
	DebugInfoAssertion   []LogEntry

	// Constraints
	NbConstraints   int // total number of constraints
	NbCOConstraints int // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []R1C

	// Hints
	Hints []Hint
}

// GetNbConstraints returns the number of constraints
func (r1cs *R1CS) GetNbConstraints() int {
	return r1cs.NbConstraints
}

// GetNbVariables return number of internal, secret and public variables
func (r1cs *R1CS) GetNbVariables() (internal, secret, public int) {
	internal = r1cs.NbInternalVariables
	secret = r1cs.NbSecretVariables
	public = r1cs.NbPublicVariables
	return
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (r1cs *R1CS) GetNbCoefficients() int {
	panic("not implemented")
}

// CurveID returns ecc.UNKNOWN as this is a untyped R1CS using big.Int
func (r1cs *R1CS) CurveID() ecc.ID {
	return ecc.UNKNOWN
}

// FrSize panics
func (r1cs *R1CS) FrSize() int {
	panic("not implemented")
}

// WriteTo panics (can't serialize untyped R1CS)
func (r1cs *R1CS) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented")
}

// ReadFrom panics (can't deserialize untyped R1CS)
func (r1cs *R1CS) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented")
}

// SetLoggerOutput replace existing logger output with provided one
// default uses os.Stdout
// if nil is provided, logs are not printed
func (r1cs *R1CS) SetLoggerOutput(w io.Writer) {
	panic("not implemented")
}
