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

package mimc

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestPreimage(t *testing.T) {
	assert := groth16.NewAssert(t)

	var mimcCircuit Circuit

	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &mimcCircuit)
	assert.NoError(err)

	{
		var witness Circuit
		witness.Hash.Assign(42)
		witness.PreImage.Assign(42)
		assert.ProverFailed(r1cs, &witness)
	}

	{
		var witness Circuit
		witness.PreImage.Assign(35)
		witness.Hash.Assign("16130099170765464552823636852555369511329944820189892919423002775646948828469")
		assert.ProverSucceeded(r1cs, &witness)
	}

}
