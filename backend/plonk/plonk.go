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

package plonk

import (
	"io"

	"github.com/consensys/gurvy"
)

// CS represents the constraint system which is used by PLONK
// it's underlying implementation is curve specific (i.e bn256/R1CS, ...)
type CS interface {
	io.WriterTo
	io.ReaderFrom
	GetNbConstraints() uint64
	GetNbWires() uint64
	GetNbCoefficients() int
	GetCurveID() gurvy.ID
}

// New instantiate a concrete curved-typed R1CS and return a R1CS interface
// This method exists for (de)serialization purposes
func New(curveID gurvy.ID) CS {
	var r1cs CS
	// switch curveID {
	// case gurvy.BN256:
	// 	r1cs = &backend_bn256.R1CS{}
	// case gurvy.BLS377:
	// 	r1cs = &backend_bls377.R1CS{}
	// case gurvy.BLS381:
	// 	r1cs = &backend_bls381.R1CS{}
	// case gurvy.BW761:
	// 	r1cs = &backend_bw761.R1CS{}
	// default:
	// 	panic("not implemented")
	// }
	return r1cs
}
