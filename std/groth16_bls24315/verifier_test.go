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
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	backend_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	groth16_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/groth16"
	"github.com/consensys/gnark/internal/backend/bls24-315/witness"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

//--------------------------------------------------------------------
// utils

const preimage string = "4992816046196248432836492760315135318126925090839638585255611512962528270024"
const publicHash string = "740442171083661049659184837119506324904268940878674425328909705936292585001"

type mimcCircuit struct {
	Data frontend.Variable
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *mimcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	//result := mimc.Sum(circuit.Data)
	mimc.Write(circuit.Data)
	result := mimc.Sum()
	api.AssertIsEqual(result, circuit.Hash)
	return nil
}

// Prepare the data for the inner proof.
// Returns the public inputs string of the inner proof
func generateBls24315InnerProof(t *testing.T, vk *groth16_bls24315.VerifyingKey, proof *groth16_bls24315.Proof) {

	// create a mock cs: knowing the preimage of a hash using mimc
	var circuit, w mimcCircuit
	r1cs, err := frontend.Compile(ecc.BLS24_315, r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	w.Data = preimage
	w.Hash = publicHash

	correctAssignment := witness.Witness{}

	_, err = correctAssignment.FromAssignment(&w, tVariable, false)
	if err != nil {
		t.Fatal(err)
	}

	// generate the data to return for the bls24315 proof
	var pk groth16_bls24315.ProvingKey
	groth16_bls24315.Setup(r1cs.(*backend_bls24315.R1CS), &pk, vk)
	_proof, err := groth16_bls24315.Prove(r1cs.(*backend_bls24315.R1CS), &pk, correctAssignment, backend.ProverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	proof.Ar = _proof.Ar
	proof.Bs = _proof.Bs
	proof.Krs = _proof.Krs

	correctAssignmentPublic := witness.Witness{}
	_, err = correctAssignmentPublic.FromAssignment(&w, tVariable, true)
	if err != nil {
		t.Fatal(err)
	}

	// before returning verifies that the proof passes on bls24315
	if err := groth16_bls24315.Verify(proof, vk, correctAssignmentPublic); err != nil {
		t.Fatal(err)
	}
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

	// get the data
	var innerVk groth16_bls24315.VerifyingKey
	var innerProof groth16_bls24315.Proof
	generateBls24315InnerProof(t, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1 = make([]sw_bls24315.G1Affine, len(innerVk.G1.K))

	// create assignment, the private part consists of the proof,
	// the public part is exactly the public part of the inner proof,
	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
	var witness verifierCircuit
	witness.InnerProof.Ar.Assign(&innerProof.Ar)
	witness.InnerProof.Krs.Assign(&innerProof.Krs)
	witness.InnerProof.Bs.Assign(&innerProof.Bs)

	// compute vk.e
	e, err := bls24315.Pair([]bls24315.G1Affine{innerVk.G1.Alpha}, []bls24315.G2Affine{innerVk.G2.Beta})
	if err != nil {
		t.Fatal(err)
	}
	witness.InnerVk.E.Assign(&e)

	witness.InnerVk.G1 = make([]sw_bls24315.G1Affine, len(innerVk.G1.K))
	for i, vkg := range innerVk.G1.K {
		witness.InnerVk.G1[i].Assign(&vkg)
	}
	var deltaNeg, gammaNeg bls24315.G2Affine
	deltaNeg.Neg(&innerVk.G2.Delta)
	gammaNeg.Neg(&innerVk.G2.Gamma)
	witness.InnerVk.G2.DeltaNeg.Assign(&deltaNeg)
	witness.InnerVk.G2.GammaNeg.Assign(&gammaNeg)
	witness.Hash = publicHash

	// verifies the cs
	assert := test.NewAssert(t)

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

	/* comment from here */

	// TODO uncommenting the lines below yield incredibly long testing time (due to the setup)
	// generate groth16 instance on bw6633 (setup, prove, verify)
	// var vk groth16_bw6633.VerifyingKey
	// var pk groth16_bw6633.ProvingKey

	// groth16_bw6633.Setup(&r1cs, &pk, &vk)
	// proof, err := groth16_bw6633.Prove(&r1cs, &pk, correctAssignment)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// res, err := groth16_bw6633.Verify(proof, &vk, correctAssignment)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// if !res {
	// 	t.Fatal("correct proof should pass")
	// }

}

func BenchmarkCompile(b *testing.B) {
	// get the data
	var innerVk groth16_bls24315.VerifyingKey
	var innerProof groth16_bls24315.Proof
	generateBls24315InnerProof(nil, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1 = make([]sw_bls24315.G1Affine, len(innerVk.G1.K))

	var ccs frontend.CompiledConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, _ = frontend.Compile(ecc.BW6_633, r1cs.NewBuilder, &circuit)
	}
	b.Log(ccs.GetNbConstraints())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
