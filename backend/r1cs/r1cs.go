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

// Package r1cs expose the R1CS (rank-1 constraint system) interface
package r1cs

import (
	"io"

	backend_bls377 "github.com/consensys/gnark/internal/backend/bls377"
	backend_bls381 "github.com/consensys/gnark/internal/backend/bls381"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256"
	backend_bw761 "github.com/consensys/gnark/internal/backend/bw761"
	"github.com/consensys/gurvy"
)

// R1CS represents a rank 1 constraint system
// it's underlying implementation is curve specific (i.e bn256/R1CS, ...)
type R1CS interface {
	io.WriterTo
	io.ReaderFrom
	GetNbConstraints() uint64
	GetNbWires() uint64
	GetNbCoefficients() int
	GetCurveID() gurvy.ID
}

// New instantiate a concrete curved-typed R1CS and return a R1CS interface
// This method exists for (de)serialization purposes
func New(curveID gurvy.ID) R1CS {
	var r1cs R1CS
	switch curveID {
	case gurvy.BN256:
		r1cs = &backend_bn256.R1CS{}
	case gurvy.BLS377:
		r1cs = &backend_bls377.R1CS{}
	case gurvy.BLS381:
		r1cs = &backend_bls381.R1CS{}
	case gurvy.BW761:
		r1cs = &backend_bw761.R1CS{}
	default:
		panic("not implemented")
	}
	return r1cs
}
