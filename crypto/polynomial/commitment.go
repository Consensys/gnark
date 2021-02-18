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

	// BatchOpenSinglePoint creates a batch opening proof at _val of _p..., by computing
	// an opening proof for for _p... bundled like _p[0]+challenge*_p[1]+challenge**2*_p[2]...
	// This pattern works to the homomorphic property of the commitment scheme.
	BatchOpenSinglePoint(_val, challenge interface{}, _p ...Polynomial) BatchOpeningProofSinglePoint
	BatchVerifySinglePoint(_val, challenge interface{}, d ...Digest) bool
}
