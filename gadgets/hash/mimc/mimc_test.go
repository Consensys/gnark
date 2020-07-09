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
	"fmt"
	"math/big"
	"testing"

	backend_bls377 "github.com/consensys/gnark/backend/bls377"
	backend_bls381 "github.com/consensys/gnark/backend/bls381"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/groth16"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"

	mimcbls377 "github.com/consensys/gnark/crypto/hash/mimc/bls377"
	mimcbls381 "github.com/consensys/gnark/crypto/hash/mimc/bls381"
	mimcbn256 "github.com/consensys/gnark/crypto/hash/mimc/bn256"

	fr_bls377 "github.com/consensys/gurvy/bls377/fr"
	fr_bls381 "github.com/consensys/gurvy/bls381/fr"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

// TODO need tests on MiMC edge cases, bad or un-allocated inputs, and errors
func TestMimcBN256(t *testing.T) {

	assertbn256 := groth16.NewAssert(t)

	// input
	var databn256 fr_bn256.Element
	databn256.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// running MiMC (R1CS)
	mimcGadget, err := NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// minimal circuit res = hash(data)
	circuit := frontend.New()
	result := mimcGadget.Hash(&circuit, circuit.PUBLIC_INPUT("data"))
	result.Tag("res")

	// running MiMC (Go)
	expectedValues := make(map[string]interface{})
	b := mimcbn256.Sum("seed", databn256.Bytes())
	var tmp fr_bn256.Element
	tmp.SetBytes(b)
	fmt.Println(tmp.String())
	expectedValues["res"] = tmp

	// provide inputs to the circuit
	inputs := make(map[string]interface{})
	inputs["data"] = databn256

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)

}

func TestMimcBLS381(t *testing.T) {

	assertbls381 := groth16.NewAssert(t)

	// input
	var data big.Int
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487", 10)
	var databls381 fr_bls381.Element
	databls381.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// running MiMC (R1CS)
	mimcGadget, err := NewMiMCGadget("seed", gurvy.BLS381)
	if err != nil {
		t.Fatal(err)
	}

	// minimal circuit res = hash(data)
	circuit := frontend.New()
	result := mimcGadget.Hash(&circuit, circuit.PUBLIC_INPUT("data"))
	result.Tag("res")

	// running MiMC (Go)
	expectedValues := make(map[string]interface{})
	b := mimcbls381.Sum("seed", databls381.Bytes())
	var tmp fr_bls381.Element
	tmp.SetBytes(b)
	expectedValues["res"] = tmp

	// provide inputs to the circuit
	inputs := make(map[string]interface{})
	inputs["data"] = data

	// creates r1cs
	r1csbls381 := circuit.ToR1CS().ToR1CS(gurvy.BLS381).(*backend_bls381.R1CS)

	assertbls381.CorrectExecution(r1csbls381, inputs, expectedValues)

}

func TestMimcBLS377(t *testing.T) {

	assertbls377 := groth16.NewAssert(t)

	// input
	var data big.Int
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487", 10)
	var databls377 fr_bls377.Element
	databls377.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// running MiMC (R1CS)
	mimcGadget, err := NewMiMCGadget("seed", gurvy.BLS377)
	if err != nil {
		t.Fatal(err)
	}

	// minimal circuit res = hash(data)
	circuit := frontend.New()
	result := mimcGadget.Hash(&circuit, circuit.PUBLIC_INPUT("data"))
	result.Tag("res")

	// running MiMC (Go)
	expectedValues := make(map[string]interface{})
	b := mimcbls377.Sum("seed", databls377.Bytes())
	var tmp fr_bls377.Element
	tmp.SetBytes(b)
	expectedValues["res"] = tmp

	// provide inputs to the circuit
	inputs := make(map[string]interface{})
	inputs["data"] = data

	// creates r1cs
	r1csbls377 := circuit.ToR1CS().ToR1CS(gurvy.BLS377).(*backend_bls377.R1CS)

	assertbls377.CorrectExecution(r1csbls377, inputs, expectedValues)

}
