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

package frontend

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
)

// CompiledConstraintSystem interface that a compiled (=typed, and correctly routed)
// should implement.
type CompiledConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// IsSolved returns nil if given witness solves the constraint system and error otherwise
	IsSolved(witness *witness.Witness, opts ...backend.ProverOption) error

	// GetNbVariables return number of internal, secret and public Variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	CurveID() ecc.ID
	FrSize() int

	// GetCounters return the collected constraint counters, if any
	GetCounters() []compiled.Counter

	GetSchema() *schema.Schema

	// GetConstraints return a human readable representation of the constraints
	GetConstraints() [][]string
}
