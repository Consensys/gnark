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
	"math/big"
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend/schema"
)

// Term lightweight version of a term, no pointers. A term packs wireID, coeffID, visibility and
// some metadata associated with the term, in a uint64.
// note: if we support more than 1 billion constraints, this breaks (not so soon.)
type Term uint64

// ids of the coefficients with simple values in any cs.coeffs slice.
const (
	CoeffIdZero     = 0
	CoeffIdOne      = 1
	CoeffIdTwo      = 2
	CoeffIdMinusOne = 3
)

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

// TermDelimitor is reserved for internal use
// the constraint solver will evaluate the sum of all terms appearing between two TermDelimitor
const TermDelimitor Term = Term(maskDelimitor)

const (
	shiftWireID             = 0
	shiftCoeffID            = nbBitsWireID
	shiftDelimitor          = shiftCoeffID + nbBitsCoeffID
	shiftFutureUse          = shiftDelimitor + nbBitsDelimitor
	shiftVariableVisibility = shiftFutureUse + nbBitsFutureUse
)

const (
	maskWireID             = uint64((1 << nbBitsWireID) - 1)
	maskCoeffID            = uint64((1<<nbBitsCoeffID)-1) << shiftCoeffID
	maskDelimitor          = uint64((1<<nbBitsDelimitor)-1) << shiftDelimitor
	maskFutureUse          = uint64((1<<nbBitsFutureUse)-1) << shiftFutureUse
	maskVariableVisibility = uint64((1<<nbBitsVariableVisibility)-1) << shiftVariableVisibility
)

// Pack packs variableID, coeffID and coeffValue into Term
// first 5 bits are reserved to encode visibility of the constraint and coeffValue of the coefficient
// next 30 bits represented the coefficient idx (in r1cs.Coefficients) by which the wire is multiplied
// next 29 bits represent the constraint used to compute the wire
// if we support more than 500 millions constraints, this breaks (not so soon.)
func Pack(variableID, coeffID int, variableVisiblity schema.Visibility) Term {
	var t Term
	t.SetWireID(variableID)
	t.SetCoeffID(coeffID)
	t.SetVariableVisibility(variableVisiblity)
	return t
}

// Unpack returns coeffID, variableID and visibility
func (t Term) Unpack() (coeffID, variableID int, variableVisiblity schema.Visibility) {
	coeffID = t.CoeffID()
	variableID = t.WireID()
	variableVisiblity = t.VariableVisibility()
	return
}

// VariableVisibility returns encoded schema.Visibility attribute
func (t Term) VariableVisibility() schema.Visibility {
	variableVisiblity := (uint64(t) & maskVariableVisibility) >> shiftVariableVisibility
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
func (t *Term) SetVariableVisibility(v schema.Visibility) {
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
	*t = Term((uint64(*t) & (^maskVariableVisibility)) | variableVisiblity)
}

// SetCoeffID update the bits correponding to the coeffID with cID
func (t *Term) SetCoeffID(cID int) {
	_coeffID := uint64(cID)
	if (_coeffID & (maskCoeffID >> shiftCoeffID)) != uint64(cID) {
		panic("coeffID is too large, unsupported")
	}
	_coeffID <<= shiftCoeffID
	*t = Term((uint64(*t) & (^maskCoeffID)) | _coeffID)
}

// SetWireID update the bits correponding to the variableID with cID
func (t *Term) SetWireID(cID int) {
	_variableID := uint64(cID)
	if (_variableID & maskWireID) != uint64(cID) {
		panic("variableID is too large, unsupported")
	}
	*t = Term((uint64(*t) & (^maskWireID)) | _variableID)
}

// WireID returns the variableID (see R1CS data structure)
func (t Term) WireID() int {
	return int((uint64(t) & maskWireID))
}

// CoeffID returns the coefficient id (see R1CS data structure)
func (t Term) CoeffID() int {
	return int((uint64(t) & maskCoeffID) >> shiftCoeffID)
}

func (t Term) string(sbb *strings.Builder, coeffs []big.Int) {
	sbb.WriteString(coeffs[t.CoeffID()].String())
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
