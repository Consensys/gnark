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

// Term lightweight version of a term, no pointers
// first 4 bits are reserved
// next 30 bits represented the coefficient idx (in r1cs.Coefficients) by which the wire is multiplied
// next 30 bits represent the constraint used to compute the wire
// if we support more than 1 billion constraints, this breaks (not so soon.)
type Term uint64

// ids of the coefficients with simple values in any cs.coeffs slice.
const (
	CoeffIdZero     = 0
	CoeffIdOne      = 1
	CoeffIdTwo      = 2
	CoeffIdMinusOne = 3
)

const (
	_                uint64 = 0b00
	variablePublic   uint64 = 0b01
	variableSecret   uint64 = 0b11
	variableInternal uint64 = 0b10
)

const (
	nbBitsVariableID         = 29
	nbBitsCoeffID            = 30
	nbBitsFutureUse          = 3
	nbBitsVariableVisibility = 2
)

const (
	shiftVariableID         = 0
	shiftCoeffID            = nbBitsVariableID
	shiftFutureUse          = shiftCoeffID + nbBitsCoeffID
	shiftVariableVisibility = shiftFutureUse + nbBitsFutureUse
)

const (
	maskVariableID         = uint64((1 << nbBitsVariableID) - 1)
	maskCoeffID            = uint64((1<<nbBitsCoeffID)-1) << shiftCoeffID
	maskFutureUse          = uint64((1<<nbBitsFutureUse)-1) << shiftFutureUse
	maskVariableVisibility = uint64((1<<nbBitsVariableVisibility)-1) << shiftVariableVisibility
)

// Pack packs variableID, coeffID and coeffValue into Term
// first 5 bits are reserved to encode visibility of the constraint and coeffValue of the coefficient
// next 30 bits represented the coefficient idx (in r1cs.Coefficients) by which the wire is multiplied
// next 29 bits represent the constraint used to compute the wire
// if we support more than 500 millions constraints, this breaks (not so soon.)
func Pack(variableID, coeffID int, variableVisiblity Visibility) Term {
	var t Term
	t.SetVariableID(variableID)
	t.SetCoeffID(coeffID)
	t.SetVariableVisibility(variableVisiblity)
	return t
}

// Unpack returns coeffID, variableID and visibility
func (t Term) Unpack() (coeffID, variableID int, variableVisiblity Visibility) {
	coeffID = t.CoeffID()
	variableID = t.VariableID()
	variableVisiblity = t.VariableVisibility()
	return
}

// VariableVisibility returns encoded Visibility attribute
func (t Term) VariableVisibility() Visibility {
	variableVisiblity := (uint64(t) & maskVariableVisibility) >> shiftVariableVisibility
	switch variableVisiblity {
	case variableInternal:
		return Internal
	case variablePublic:
		return Public
	case variableSecret:
		return Secret
	default:
		return Unset
	}
}

// SetVariableVisibility update the bits correponding to the variableVisiblity with its encoding
func (t *Term) SetVariableVisibility(v Visibility) {
	variableVisiblity := uint64(0)
	switch v {
	case Internal:
		variableVisiblity = variableInternal
	case Public:
		variableVisiblity = variablePublic
	case Secret:
		variableVisiblity = variableSecret
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

// SetVariableID update the bits correponding to the variableID with cID
func (t *Term) SetVariableID(cID int) {
	_variableID := uint64(cID)
	if (_variableID & maskVariableID) != uint64(cID) {
		panic("variableID is too large, unsupported")
	}
	*t = Term((uint64(*t) & (^maskVariableID)) | _variableID)
}

// VariableID returns the variableID (see R1CS data structure)
func (t Term) VariableID() int {
	return int((uint64(t) & maskVariableID))
}

// CoeffID returns the coefficient id (see R1CS data structure)
func (t Term) CoeffID() int {
	return int((uint64(t) & maskCoeffID) >> shiftCoeffID)
}
