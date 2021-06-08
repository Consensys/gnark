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

package exponentiate

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestExponentiateGroth16(t *testing.T) {

	assert := groth16.NewAssert(t)

	var expCircuit Circuit
	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &expCircuit)
	if err != nil {
		t.Fatal(err)
	}

	{
		var witness Circuit
		witness.X.Assign(2)
		witness.E.Assign(12)
		witness.Y.Assign(4095)
		assert.ProverFailed(r1cs, &witness) // y != x**e
	}

	{
		var witness Circuit
		witness.X.Assign(2)
		witness.E.Assign(12)
		witness.Y.Assign(4096)
		assert.ProverSucceeded(r1cs, &witness)
	}

}
