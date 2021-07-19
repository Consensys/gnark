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

// Package backend implements Zero Knowledge Proof systems: it consumes circuit compiled with gnark/frontend.
package backend

// ID represent a unique ID for a proving scheme
type ID uint16

const (
	UNKNOWN ID = iota
	GROTH16
	PLONK
)

// Implemented return the list of proof systems implemented in gnark
func Implemented() []ID {
	return []ID{GROTH16, PLONK}
}

// String returns the string representation of a proof system
func (id ID) String() string {
	switch id {
	case GROTH16:
		return "groth16"
	case PLONK:
		return "plonk"
	default:
		return "unknown"
	}
}
