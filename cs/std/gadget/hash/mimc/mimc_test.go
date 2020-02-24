// +build bn256 bls381 bls377

/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mimc

import (
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/internal/curve"
	mimcgo "github.com/consensys/gnark/cs/std/reference/hash/mimc"
)

// TODO need tests on MiMC edge cases, bad or un-allocated inputs, and errors
func TestMimc(t *testing.T) {

	assert := cs.NewAssert(t)

	// input
	var data curve.Element
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// running MiMC (R1CS)
	mimc := NewMiMC("seed")

	// minimal circuit res = hash(data)
	s := cs.New()
	result := mimc.Hash(&s, s.PUBLIC_INPUT("data"))
	result.Tag("res")

	// running MiMC (Go)
	expectedValues := make(map[string]interface{})
	expectedValues["res"] = mimcgo.NewMiMC("seed").Hash(data)

	// provide inputs to the circuit
	inputs := cs.NewAssignment()
	inputs.Assign(cs.Public, "data", data)

	assert.Solved(s, inputs, expectedValues)

}
