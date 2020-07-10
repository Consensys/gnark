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

package backend

import "errors"

// OneWire is the assignment label / name used for the constant wire one
const OneWire = "ONE_WIRE"

// Visibility type alias on string to define circuit input's visibility
type Visibility string

// Possible Visibility attributes for circuit inputs
const (
	Secret Visibility = "secret"
	Public Visibility = "public"
)

func ErrDuplicateTag(tag string) error {
	return errors.New("duplicate tag: " + tag)
}

var (
	ErrInputNotSet           = errors.New("input not set")
	ErrInputVisiblity        = errors.New("input has incorrect visibility (secret / public)")
	ErrUnsatisfiedConstraint = errors.New("constraint is not satisfied")
	ErrInvalidInputFormat    = errors.New("incorrect input format")
)

// SolvingMethod is used by the R1CS solver
// note: it is not in backend/r1cs to avoid an import cycle
type SolvingMethod uint8

const (
	SingleOutput SolvingMethod = iota
	BinaryDec
)
