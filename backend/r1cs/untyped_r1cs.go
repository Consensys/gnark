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
	NbWires       int
	NbPublicWires int // includes ONE wire
	NbSecretWires int
	SecretWires   []string // private wire names
	PublicWires   []string // public wire names
	Logs          []backend.LogEntry
	DebugInfo     []backend.LogEntry

	// Constraints
	NbConstraints   int // total number of constraints
	NbCOConstraints int // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []r1c.R1C
	Coefficients    []big.Int
}

// GetNbConstraints returns the number of constraints
func (r1cs *UntypedR1CS) GetNbConstraints() int {
	return r1cs.NbConstraints
}

// GetNbWires returns the number of wires
func (r1cs *UntypedR1CS) GetNbWires() int {
	return r1cs.NbWires
}

// GetNbCoefficients return the number of (different) coefficients needed in the R1CS
func (r1cs *UntypedR1CS) GetNbCoefficients() int {
	return len(r1cs.Coefficients)
}

// GetCurveID returns gurvy.UNKNOWN as this R1CS is Untyped and have big.Int coefficients
func (r1cs *UntypedR1CS) GetCurveID() gurvy.ID {
	return gurvy.UNKNOWN
}

// IsSolved call will panic as we can't solve a UntypedR1CS
func (r1cs *UntypedR1CS) IsSolved(solution map[string]interface{}) error {
	panic("not implemented")
}

// ToR1CS will convert the big.Int coefficients in the UntypedR1CS to field elements
// in the basefield of the provided curveID and return a R1CS
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
