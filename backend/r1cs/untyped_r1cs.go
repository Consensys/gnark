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
	"github.com/consensys/gnark/backend/r1cs/term"
	"github.com/consensys/gurvy"
)

// UntypedR1CS decsribes a set of UntypedR1CS constraint
// The coefficients from the rank-1 constraint it contains
// are big.Int and not tied to a curve base field
type UntypedR1CS struct {
	// Wires
	NbWires        int
	NbPublicWires  int // includes ONE wire
	NbPrivateWires int
	PrivateWires   []string         // private wire names
	PublicWires    []string         // public wire names
	WireTags       map[int][]string // optional tags -- debug info

	// Constraints
	NbConstraints   int // total number of constraints
	NbCOConstraints int // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []R1C
	Coefficients    []big.Int
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

// // Term coeff * constraint (ID)
// type Term struct {
// 	ID    int     // index of the constraint used to compute this wire
// 	Coeff big.Int // coefficient by which the wire is multiplied
// }

// LinearExpression represent a linear expression of variables
type LinearExpression []term.Term

// R1C used to compute the wires
type R1C struct {
	L      LinearExpression
	R      LinearExpression
	O      LinearExpression
	Solver backend.SolvingMethod
}
