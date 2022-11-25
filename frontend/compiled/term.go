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
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend/field"
	"github.com/consensys/gnark/frontend/schema"
)

// Term represents a single term in a linear expression. It consists of
// coefficient and a variable, which will be solved and filled by the prover.
// Variable packs wire ID, coefficient and additional metadata.
type Term[E field.El, ptE field.PtEl[E]] struct {
	// Coeff is the actual coefficient of the term.
	Coeff E
	// Var is the variable data. First 5 bits are reserved to encode visibility
	// of the constraint. Next 30 bits are empty (were used for encoding the
	// coefficient). Next 29 bits represent the constraint used to compute the
	// wire (supports up to 2^29 ~~ 500M constraints).
	Var uint64
}

const (
	_                uint64 = 0b000
	variablePublic   uint64 = 0b001
	variableSecret   uint64 = 0b010
	variableInternal uint64 = 0b011
	variableVirtual  uint64 = 0b100
)

const (
	nbBitsWireID             = 29
	nbBitsCoeffID            = 30
	nbBitsDelimitor          = 1
	nbBitsFutureUse          = 1
	nbBitsVariableVisibility = 3
)

// TermDelimitor returns a term which acts as a delimitor in a linear expression
// for partitioning. The solver will evaluate the sum of all terms appearing
// between two delimiting Terms.
func TermDelimitor[E field.El, ptE field.PtEl[E]]() Term[E, ptE] {
	return Term[E, ptE]{Var: maskDelimitor}
}

const (
	shiftCoeffID            = nbBitsWireID
	shiftDelimitor          = shiftCoeffID + nbBitsCoeffID
	shiftFutureUse          = shiftDelimitor + nbBitsDelimitor
	shiftVariableVisibility = shiftFutureUse + nbBitsFutureUse
)

const (
	maskWireID             = uint64((1 << nbBitsWireID) - 1)
	maskCoeffID            = uint64((1<<nbBitsCoeffID)-1) << shiftCoeffID
	maskDelimitor          = uint64((1<<nbBitsDelimitor)-1) << shiftDelimitor
	_                      = uint64((1<<nbBitsFutureUse)-1) << shiftFutureUse
	maskVariableVisibility = uint64((1<<nbBitsVariableVisibility)-1) << shiftVariableVisibility
)

// Pack packs variableID, coeff and variableVisibility into Term.
func Pack[E field.El, ptE field.PtEl[E]](variableID int, coeff E, variableVisiblity schema.Visibility) Term[E, ptE] {
	t := Term[E, ptE]{
		Coeff: coeff,
	}
	t.SetWireID(variableID)
	t.SetVariableVisibility(variableVisiblity)
	return t
}

func PackInt64[E field.El, ptE field.PtEl[E]](variableID int, coeff int64, variableVisibility schema.Visibility) Term[E, ptE] {
	var e E
	ptE(&e).SetInt64(coeff)
	return Pack[E, ptE](variableID, e, variableVisibility)
}

// Unpack returns coeffID, variableID and visibility
func (t Term[E, ptE]) Unpack() (coeff E, variableID int, variableVisiblity schema.Visibility) {
	coeff = t.Coeff
	variableID = t.WireID()
	variableVisiblity = t.VariableVisibility()
	return
}

// VariableVisibility returns encoded schema.Visibility attribute
func (t Term[E, ptE]) VariableVisibility() schema.Visibility {
	variableVisiblity := (uint64(t.Var) & maskVariableVisibility) >> shiftVariableVisibility
	switch variableVisiblity {
	case variableInternal:
		return schema.Internal
	case variablePublic:
		return schema.Public
	case variableSecret:
		return schema.Secret
	case variableVirtual:
		return schema.Virtual
	default:
		return schema.Unset
	}
}

// SetVariableVisibility update the bits correponding to the variableVisiblity with its encoding
func (t *Term[E, ptE]) SetVariableVisibility(v schema.Visibility) {
	variableVisiblity := uint64(0)
	switch v {
	case schema.Internal:
		variableVisiblity = variableInternal
	case schema.Public:
		variableVisiblity = variablePublic
	case schema.Secret:
		variableVisiblity = variableSecret
	case schema.Virtual:
		variableVisiblity = variableVirtual
	default:
		return
	}
	variableVisiblity <<= shiftVariableVisibility
	t.Var = (uint64(t.Var) & (^maskVariableVisibility)) | variableVisiblity
}

// SetWireID update the bits correponding to the variableID with cID
func (t *Term[E, ptE]) SetWireID(cID int) {
	_variableID := uint64(cID)
	if (_variableID & maskWireID) != uint64(cID) {
		panic("variableID is too large, unsupported")
	}
	t.Var = (uint64(t.Var) & (^maskWireID)) | _variableID
}

// WireID returns the variableID (see R1CS data structure)
func (t Term[E, ptE]) WireID() int {
	return int((uint64(t.Var) & maskWireID))
}

// IsDelimitor returns if
func (t Term[E, ptE]) IsDelimitor() bool {
	return (t.Var & maskDelimitor) != 0
}

func (t Term[E, ptE]) string(sbb *strings.Builder) {
	sbb.WriteString(ptE(&t.Coeff).String())
	sbb.WriteString("*")
	switch t.VariableVisibility() {
	case schema.Internal:
		sbb.WriteString("i")
	case schema.Public:
		sbb.WriteString("p")
	case schema.Secret:
		sbb.WriteString("s")
	case schema.Virtual:
		sbb.WriteString("v")
	case schema.Unset:
		sbb.WriteString("u")
	default:
		panic("not implemented")
	}
	sbb.WriteString(strconv.Itoa(t.WireID()))
}

func (t Term[E, ptE]) HashCode() uint64 {
	return t.Var
}

func (t Term[E, ptE]) IsZero() bool {
	return ptE(&t.Coeff).IsZero()
}

func (t Term[E, ptE]) IsOne() bool {
	return ptE(&t.Coeff).IsOne()
}

func (t Term[E, ptE]) IsNegOne() bool {
	var nOne E
	ptE(&nOne).SetOne()
	ptE(&nOne).Neg(&nOne)
	return ptE(&t.Coeff).Equal(&nOne)
}

func (t *Term[E, ptE]) SetCoeff(coeff E) {
	t.Coeff = coeff
}
