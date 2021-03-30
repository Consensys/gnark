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
	"math/big"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/crypto/hash"
	"github.com/consensys/gurvy/ecc"
)

type mimcCircuit struct {
	ExpectedResult frontend.Variable `gnark:"data,public"`
	Data           frontend.Variable
}

func (circuit *mimcCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	result := mimc.Hash(cs, circuit.Data)
	cs.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

func TestMimcAll(t *testing.T) {
	assert := groth16.NewAssert(t)

	// input
	var data, tamperedData big.Int
	data.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919487", 10)
	tamperedData.SetString("7808462342289447506325013279997289618334122576263655295146895675168642919488", 10)

	curves := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BW6_761:   hash.MIMC_BW6_761,
	}

	for curve, hashFunc := range curves {

		// minimal cs res = hash(data)
		var circuit, witness, wrongWitness mimcCircuit
		r1cs, err := frontend.Compile(curve, backend.GROTH16, &circuit)
		if err != nil {
			t.Fatal(err)
		}

		// running MiMC (Go)
		goMimc := hashFunc.New("seed")
		goMimc.Write(data.Bytes())
		b := goMimc.Sum(nil)

		// assert correctness against correct witness
		witness.Data.Assign(data)
		witness.ExpectedResult.Assign(b)
		assert.SolvingSucceeded(r1cs, &witness)

		// assert failure against wrong witness
		wrongWitness.Data.Assign(tamperedData)
		wrongWitness.ExpectedResult.Assign(b)
		assert.SolvingFailed(r1cs, &wrongWitness)
	}

}
