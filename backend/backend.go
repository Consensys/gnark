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

// Package backend provides circuit arithmetic representations and zero knowledge proof APIs.
//
// Functions is this package are not curve specific and point to internal/backend curve specific
// implementation when needed
package backend

import "errors"

const (
	UNKNOWN ID = iota
	GROTH16
	PLONK
)

// ID represent a unique ID for a proving scheme
type ID uint16

// ErrInputNotSet can be generated when solving the R1CS (a missing assignment) or running a Verifier
var ErrInputNotSet = errors.New("variable is not allocated")

// ErrUnsatisfiedConstraint can be generated when solving a R1CS
var ErrUnsatisfiedConstraint = errors.New("constraint is not satisfied")

// note: this types are shared between frontend and backend packages and are here to avoid import cycles
// probably need a better naming / home for them

// LogEntry is used as a shared data structure between the frontend and the backend
// to represent string values (in logs or debug info) where a value is not known at compile time
// (which is the case for variables that need to be resolved in the R1CS)
type LogEntry struct {
	Format    string
	ToResolve []int
}

// Visibility encodes a Variable (or wire) visibility
// Possible values are Unset, Internal, Secret or Public
type Visibility uint8

const (
	Unset Visibility = iota
	Internal
	Secret
	Public
)
