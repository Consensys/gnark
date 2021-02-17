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

// FieldElmt represents a field element
type FieldElmt interface{}

// Polynomial interface that a polynomial should implement
type Polynomial interface {
	Degree() uint64
}

// Digest interface that a polynomial commitment should implement
type Digest interface {
	io.WriterTo
	io.ReaderFrom
}

// OpeningProof interface that a polynomial commitment opening proof
// should implement.
type OpeningProof interface {
	io.WriterTo
	io.ReaderFrom

	// ClaimedValue returns the claimed value from the proof
	ClaimedValue() FieldElmt
}

// CommitmentScheme interface for a polynomial commitment scheme
type CommitmentScheme interface {
	io.WriterTo
	io.ReaderFrom

	Commit(p Polynomial) Digest
	Open(p Polynomial, val FieldElmt) OpeningProof
	Verify(d Digest, p OpeningProof, v FieldElmt) bool
}
