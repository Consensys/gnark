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

package groth16_bls24315

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

const (
	preImage   = "4992816046196248432836492760315135318126925090839638585255611512962528270024"
	publicHash = "4875439939758844840941638351757981379945701574516438614845550995673793857363"
)

type mimcCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *mimcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err

	}
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(mimc.Sum(), circuit.Hash)
	return nil

}

// Calculate the expected output of MIMC through plain invocation
func preComputeMimc(preImage frontend.Variable) interface{} {
	var expectedY fr.Element
	expectedY.SetInterface(preImage)
	// calc MiMC
	goMimc := hash.MIMC_BLS24_315.New()
	goMimc.Write(expectedY.Marshal())
	expectedh := goMimc.Sum(nil)
	return expectedh

}

type verifierCircuit struct {
	InnerProof Proof
	InnerVk    VerifyingKey
	Hash       frontend.Variable
}

func (circuit *verifierCircuit) Define(api frontend.API) error {
	// create the verifier cs
	Verify(api, circuit.InnerVk, circuit.InnerProof, []frontend.Variable{circuit.Hash})

	return nil

}

func TestVerifier(t *testing.T) {

	// create a mock cs: knowing the preimage of a hash using mimc
	var MimcCircuit mimcCircuit
	r1cs, err := frontend.Compile(ecc.BLS24_315.ScalarField(), r1cs.NewBuilder, &MimcCircuit)
	if err != nil {
		t.Fatal(err)

	}

	var pre_assignment mimcCircuit
	pre_assignment.PreImage = preImage
	pre_assignment.Hash = publicHash
	pre_witness, err := frontend.NewWitness(&pre_assignment, ecc.BLS24_315.ScalarField())
	if err != nil {
		t.Fatal(err)

	}

	innerPk, innerVk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Fatal(err)

	}

	proof, err := groth16.Prove(r1cs, innerPk, pre_witness)
	if err != nil {
		t.Fatal(err)

	}

	publicWitness, err := pre_witness.Public()
	if err != nil {
		t.Fatal(err)

	}

	// Check that proof verifies before continuing
	if err := groth16.Verify(proof, innerVk, publicWitness); err != nil {
		t.Fatal(err)

	}

	var circuit verifierCircuit
	circuit.InnerVk.FillG1K(innerVk)

	var witness verifierCircuit
	witness.InnerProof.Assign(proof)
	witness.InnerVk.Assign(innerVk)
	witness.Hash = preComputeMimc(preImage)

	assert := test.NewAssert(t)

	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633), test.WithBackends(backend.GROTH16))

}

func BenchmarkCompile(b *testing.B) {

	// create a mock cs: knowing the preimage of a hash using mimc
	var MimcCircuit mimcCircuit
	_r1cs, err := frontend.Compile(ecc.BLS24_315.ScalarField(), r1cs.NewBuilder, &MimcCircuit)
	if err != nil {
		b.Fatal(err)

	}

	var pre_assignment mimcCircuit
	pre_assignment.PreImage = preImage
	pre_assignment.Hash = publicHash
	pre_witness, err := frontend.NewWitness(&pre_assignment, ecc.BLS24_315.ScalarField())
	if err != nil {
		b.Fatal(err)

	}

	innerPk, innerVk, err := groth16.Setup(_r1cs)
	if err != nil {
		b.Fatal(err)

	}

	proof, err := groth16.Prove(_r1cs, innerPk, pre_witness)
	if err != nil {
		b.Fatal(err)

	}

	publicWitness, err := pre_witness.Public()
	if err != nil {
		b.Fatal(err)

	}

	// Check that proof verifies before continuing
	if err := groth16.Verify(proof, innerVk, publicWitness); err != nil {
		b.Fatal(err)

	}

	var circuit verifierCircuit
	circuit.InnerVk.FillG1K(innerVk)

	var ccs constraint.ConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, err = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			b.Fatal(err)

		}

	}

	b.Log(ccs.GetNbConstraints())

}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()

}
