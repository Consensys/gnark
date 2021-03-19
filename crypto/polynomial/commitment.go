// Copyright 2020 ConsenSys Software Inc.
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

package polynomial

import "io"

// Polynomial interface that a polynomial should implement
type Polynomial interface {
	Degree() uint64
	Eval(v interface{}) interface{}
}

// Digest interface that a polynomial commitment should implement
type Digest interface {
	io.WriterTo
	io.ReaderFrom
}

// OpeningProof interface that an opening proof
// should implement.
type OpeningProof interface {
	io.WriterTo
	io.ReaderFrom
}

// BatchOpeningProofSinglePoint interface that a bacth opening proof (single point)
// should implement.
type BatchOpeningProofSinglePoint interface {
	io.WriterTo
	io.ReaderFrom
}

// CommitmentScheme interface for an additively homomorphic
// polynomial commitment scheme.
// The function BatchOpenSinglePoint is proper to an additively
// homomorphic commitment scheme.
type CommitmentScheme interface {
	io.WriterTo
	io.ReaderFrom

	Commit(p Polynomial) Digest

	Open(val interface{}, p Polynomial) OpeningProof
	Verify(d Digest, p OpeningProof, v interface{}) bool

	// BatchOpenSinglePoint creates a batch opening proof at _val of a list of polynomials.
	// It's an interactive protocol, made non interactive using Fiat Shamir.
	BatchOpenSinglePoint(point interface{}, polynomials interface{}) BatchOpeningProofSinglePoint

	// BatchVerifySinglePoint verifies a batched opening proof at a single point of a list of polynomials.
	// point: point at which the polynomials are evaluated
	// claimedValues: claimed values of the polynomials at _val
	// commitments: list of commitments to the polynomials which are opened
	// batchOpeningProof: the batched opening proof at a single point of the polynomials.
	BatchVerifySinglePoint(
		point interface{},
		claimedValues interface{},
		commitments interface{},
		batchOpeningProof BatchOpeningProofSinglePoint) bool
}
