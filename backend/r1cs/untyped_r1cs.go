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
	backend_bls377 "github.com/consensys/gnark/backend/bls377"
	backend_bls381 "github.com/consensys/gnark/backend/bls381"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	backend_bw761 "github.com/consensys/gnark/backend/bw761"
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
}

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
	}
	return nil
}

// Term ...
type Term struct {
	ID    int64   // index of the constraint used to compute this wire
	Coeff big.Int // coefficient by which the wire is multiplied
}

// LinearExpression
type LinearExpression []Term

// R1C used to compute the wires
type R1C struct {
	L      LinearExpression
	R      LinearExpression
	O      LinearExpression
	Solver backend.SolvingMethod
}

func (r1cs *UntypedR1CS) toBLS381() *backend_bls381.R1CS {

	toReturn := backend_bls381.R1CS{
		NbWires:         r1cs.NbWires,
		NbPublicWires:   r1cs.NbPublicWires,
		NbPrivateWires:  r1cs.NbPrivateWires,
		PrivateWires:    r1cs.PrivateWires,
		PublicWires:     r1cs.PublicWires,
		WireTags:        r1cs.WireTags,
		NbConstraints:   r1cs.NbConstraints,
		NbCOConstraints: r1cs.NbCOConstraints,
	}
	toReturn.Constraints = make([]backend_bls381.R1C, len(r1cs.Constraints))
	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_bls381.R1C{
			Solver: from.Solver,
			L:      make(backend_bls381.LinearExpression, len(from.L)),
			R:      make(backend_bls381.LinearExpression, len(from.R)),
			O:      make(backend_bls381.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			to.L[j].ID = from.L[j].ID
			to.L[j].Coeff.SetBigInt(&from.L[j].Coeff)
		}
		for j := 0; j < len(from.R); j++ {
			to.R[j].ID = from.R[j].ID
			to.R[j].Coeff.SetBigInt(&from.R[j].Coeff)
		}
		for j := 0; j < len(from.O); j++ {
			to.O[j].ID = from.O[j].ID
			to.O[j].Coeff.SetBigInt(&from.O[j].Coeff)
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}

func (r1cs *UntypedR1CS) toBW761() *backend_bw761.R1CS {

	toReturn := backend_bw761.R1CS{
		NbWires:         r1cs.NbWires,
		NbPublicWires:   r1cs.NbPublicWires,
		NbPrivateWires:  r1cs.NbPrivateWires,
		PrivateWires:    r1cs.PrivateWires,
		PublicWires:     r1cs.PublicWires,
		WireTags:        r1cs.WireTags,
		NbConstraints:   r1cs.NbConstraints,
		NbCOConstraints: r1cs.NbCOConstraints,
	}
	toReturn.Constraints = make([]backend_bw761.R1C, len(r1cs.Constraints))
	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_bw761.R1C{
			Solver: from.Solver,
			L:      make(backend_bw761.LinearExpression, len(from.L)),
			R:      make(backend_bw761.LinearExpression, len(from.R)),
			O:      make(backend_bw761.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			to.L[j].ID = from.L[j].ID
			to.L[j].Coeff.SetBigInt(&from.L[j].Coeff)
		}
		for j := 0; j < len(from.R); j++ {
			to.R[j].ID = from.R[j].ID
			to.R[j].Coeff.SetBigInt(&from.R[j].Coeff)
		}
		for j := 0; j < len(from.O); j++ {
			to.O[j].ID = from.O[j].ID
			to.O[j].Coeff.SetBigInt(&from.O[j].Coeff)
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}

func (r1cs *UntypedR1CS) toBLS377() *backend_bls377.R1CS {

	toReturn := backend_bls377.R1CS{
		NbWires:         r1cs.NbWires,
		NbPublicWires:   r1cs.NbPublicWires,
		NbPrivateWires:  r1cs.NbPrivateWires,
		PrivateWires:    r1cs.PrivateWires,
		PublicWires:     r1cs.PublicWires,
		WireTags:        r1cs.WireTags,
		NbConstraints:   r1cs.NbConstraints,
		NbCOConstraints: r1cs.NbCOConstraints,
	}
	toReturn.Constraints = make([]backend_bls377.R1C, len(r1cs.Constraints))
	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_bls377.R1C{
			Solver: from.Solver,
			L:      make(backend_bls377.LinearExpression, len(from.L)),
			R:      make(backend_bls377.LinearExpression, len(from.R)),
			O:      make(backend_bls377.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			to.L[j].ID = from.L[j].ID
			to.L[j].Coeff.SetBigInt(&from.L[j].Coeff)
		}
		for j := 0; j < len(from.R); j++ {
			to.R[j].ID = from.R[j].ID
			to.R[j].Coeff.SetBigInt(&from.R[j].Coeff)
		}
		for j := 0; j < len(from.O); j++ {
			to.O[j].ID = from.O[j].ID
			to.O[j].Coeff.SetBigInt(&from.O[j].Coeff)
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}

func (r1cs *UntypedR1CS) toBN256() *backend_bn256.R1CS {

	toReturn := backend_bn256.R1CS{
		NbWires:         r1cs.NbWires,
		NbPublicWires:   r1cs.NbPublicWires,
		NbPrivateWires:  r1cs.NbPrivateWires,
		PrivateWires:    r1cs.PrivateWires,
		PublicWires:     r1cs.PublicWires,
		WireTags:        r1cs.WireTags,
		NbConstraints:   r1cs.NbConstraints,
		NbCOConstraints: r1cs.NbCOConstraints,
	}
	toReturn.Constraints = make([]backend_bn256.R1C, len(r1cs.Constraints))
	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_bn256.R1C{
			Solver: from.Solver,
			L:      make(backend_bn256.LinearExpression, len(from.L)),
			R:      make(backend_bn256.LinearExpression, len(from.R)),
			O:      make(backend_bn256.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			to.L[j].ID = from.L[j].ID
			to.L[j].Coeff.SetBigInt(&from.L[j].Coeff)
		}
		for j := 0; j < len(from.R); j++ {
			to.R[j].ID = from.R[j].ID
			to.R[j].Coeff.SetBigInt(&from.R[j].Coeff)
		}
		for j := 0; j < len(from.O); j++ {
			to.O[j].ID = from.O[j].ID
			to.O[j].Coeff.SetBigInt(&from.O[j].Coeff)
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}
