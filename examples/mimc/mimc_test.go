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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var mimcCircuit Circuit

	assert.ProverFailed(&mimcCircuit, []frontend.Circuit{&Circuit{
		Hash:     frontend.Value(42),
		PreImage: frontend.Value(42),
	}})

	assert.ProverSucceeded(&mimcCircuit, []frontend.Circuit{&Circuit{
		PreImage: frontend.Value(35),
		Hash:     frontend.Value("16130099170765464552823636852555369511329944820189892919423002775646948828469"),
	}}, test.WithCurves(ecc.BN254))

}
