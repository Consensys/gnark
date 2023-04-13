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

package cubic

import (
	"testing"

	"github.com/consensys/gnark/test"
)

func TestCubicEquation(t *testing.T) {
	assert := test.NewAssert(t)

	var cubicCircuit Circuit

	// ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &cubicCircuit)
	// assert.NoError(err)

	// constraints, r := ccs.(constraint.SparseR1CS).GetConstraints()
	// fmt.Println("BEGIN", ccs.GetNbConstraints(), len(constraints))
	// for _, c := range constraints {
	// 	fmt.Println(c.String(r))
	// }
	// return

	// 0 + 0 + -1⋅v0 + 1⋅(x×x) + 0 == 0
	// 0 + 0 + -1⋅v1 + 1⋅(v0×x) + 0 == 0
	// x + v1 + -1⋅v2 + 5 == 0
	// Y + -1⋅v2 + 0 + 0 == 0

	assert.ProverFailed(&cubicCircuit, &Circuit{
		X: 42,
		Y: 42,
	})

	assert.ProverSucceeded(&cubicCircuit, &Circuit{
		X: 3,
		Y: 35,
	})

}
