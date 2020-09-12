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

type mimcCircuit struct {
	Data           frontend.Variable `gnark:"data,public"`
	ExpectedResult frontend.Variable
}

func (circuit *mimcCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	result := mimc.Hash(cs, circuit.Data)
	cs.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

// TODO need tests on MiMC edge cases, bad or un-allocated inputs, and errors
func TestMimcBN256(t *testing.T) {
	assert := groth16.NewAssert(t)

	// input
	var data fr_bn256.Element
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// minimal cs res = hash(data)
	var circuit, witness mimcCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// running MiMC (Go)
	b := mimcbn256.Sum("seed", data.Bytes())
	var tmp fr_bn256.Element
	tmp.SetBytes(b)
	witness.Data.Assign(data)
	witness.ExpectedResult.Assign(tmp)

	// creates r1cs
	assert.CorrectExecution(r1cs, &witness)
}

func TestMimcBLS381(t *testing.T) {

	assert := groth16.NewAssert(t)

	// input
	var data fr_bls381.Element
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// minimal cs res = hash(data)
	var circuit, witness mimcCircuit
	r1cs, err := frontend.Compile(gurvy.BLS381, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// running MiMC (Go)
	b := mimcbls381.Sum("seed", data.Bytes())
	var tmp fr_bls381.Element
	tmp.SetBytes(b)
	witness.Data.Assign(data)
	witness.ExpectedResult.Assign(tmp)

	assert.CorrectExecution(r1cs, &witness)

}

func TestMimcBLS377(t *testing.T) {

	assert := groth16.NewAssert(t)

	// input
	var data fr_bls377.Element
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487")

	// minimal cs res = hash(data)
	var circuit, witness mimcCircuit
	r1cs, err := frontend.Compile(gurvy.BLS377, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// running MiMC (Go)
	b := mimcbls377.Sum("seed", data.Bytes())
	var tmp fr_bls377.Element
	tmp.SetBytes(b)
	witness.Data.Assign(data)
	witness.ExpectedResult.Assign(tmp)

	assert.CorrectExecution(r1cs, &witness)

}
