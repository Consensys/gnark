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

package r1cs

import (
	"io"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs/r1c"
	"github.com/consensys/gurvy"
)

// UntypedR1CS decsribes a set of UntypedR1CS constraint
// The coefficients from the rank-1 constraint it contains
// are big.Int and not tied to a curve base field
type UntypedR1CS struct {
	// Wires
	NbWires       uint64
	NbPublicWires uint64 // includes ONE wire
	NbSecretWires uint64
	Logs          []backend.LogEntry
	DebugInfo     []backend.LogEntry

	// Constraints
	NbConstraints   uint64 // total number of constraints
	NbCOConstraints uint64 // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []r1c.R1C
	Coefficients    []big.Int
}

// GetNbConstraints returns the number of constraints
func (r1cs *UntypedR1CS) GetNbConstraints() uint64 {
	return r1cs.NbConstraints
}

// GetNbWires returns the number of wires
func (r1cs *UntypedR1CS) GetNbWires() uint64 {
	return r1cs.NbWires
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (r1cs *UntypedR1CS) GetNbCoefficients() int {
	return len(r1cs.Coefficients)
}

// WriteTo panics (can't serialize untyped R1CS)
func (r1cs *UntypedR1CS) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented: can't serialize untyped R1CS")
}

// GetCurveID returns gurvy.UNKNOWN as this is a untyped R1CS using big.Int
func (r1cs *UntypedR1CS) GetCurveID() gurvy.ID {
	return gurvy.UNKNOWN
}

// ReadFrom panics (can't deserialize untyped R1CS)
func (r1cs *UntypedR1CS) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented: can't deserialize untyped R1CS")
}

// ToR1CS will convert the big.Int coefficients in the UntypedR1CS to field elements
// in the basefield of the provided curveID and return a R1CS
//
// this should not be called in a normal circuit development workflow
func (r1cs *UntypedR1CS) ToR1CS(curveID gurvy.ID) R1CS {
	switch curveID {
	case gurvy.BN256:
		return r1cs.toBN256()
	case gurvy.BLS377:
		return r1cs.toBLS377()
	case gurvy.BLS381:
		return r1cs.toBLS381()
	case gurvy.BW761:
		return r1cs.toBW761()
	default:
		panic("not implemented")
	}
}
