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

package groth16_bls12377

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	backend_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	groth16_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/groth16"
	"github.com/consensys/gnark/internal/backend/bls12-377/witness"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

const (
	preImage   = "4992816046196248432836492760315135318126925090839638585255611512962528270024"
	publicHash = "4458332240632096997117977163518118563548842578509780924154021342053538349576"
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

// Prepare the data for the inner proof.
// Returns the public inputs string of the inner proof
func generateBls12377InnerProof(t *testing.T, vk *groth16_bls12377.VerifyingKey, proof *groth16_bls12377.Proof) {

	// create a mock cs: knowing the preimage of a hash using mimc
	var circuit mimcCircuit
	r1cs, err := frontend.Compile(ecc.BLS12_377, r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// build the witness
	var assignment mimcCircuit
	assignment.PreImage = preImage
	assignment.Hash = publicHash

	var witness, publicWitness witness.Witness
	_, err = witness.FromAssignment(&assignment, tVariable, false)
	if err != nil {
		t.Fatal(err)
	}

	_, err = publicWitness.FromAssignment(&assignment, tVariable, true)
	if err != nil {
		t.Fatal(err)
	}

	// generate the data to return for the bls12377 proof
	var pk groth16_bls12377.ProvingKey
	groth16_bls12377.Setup(r1cs.(*backend_bls12377.R1CS), &pk, vk)

	_proof, err := groth16_bls12377.Prove(r1cs.(*backend_bls12377.R1CS), &pk, witness, backend.ProverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	proof.Ar = _proof.Ar
	proof.Bs = _proof.Bs
	proof.Krs = _proof.Krs

	// TODO @gbotrel clean up
	// var buf bytes.Buffer
	// vk.WriteTo(&buf)
	// fmt.Println("vk")
	// fmt.Println(hex.EncodeToString(buf.Bytes()))
	// vkBytes, _ := hex.DecodeString("a14d160fc36562208886d647809f7c05f7ae67070d93a26bf12a9afa132832732b5bd4bdd5de4bdab361d21f9711e0baa0f53216809240558b8a38c89dfa1810bff224091d68a271a439564418e8fb04d744eb4e0c1de735fdb05427484a488da164953c0da7d079780013935f183eec57e18a5cbb5f86bb309ad5b2c337f23ac9dab2549813847a450499cc97f3dac10157b1f462607594b3e53e7a9abd31e5f6690d9c886aa2e1c4a608a77d7e27dca8645837ad0c1a03193ff609b01e54af80e71a6018286563aed5e39c0b1fc1e1fc3b2433c8e94ed055b0a51a10438f2889dc48553fb38854248c74c80f8d938a013b521a9bf0623eaea275d600fc74aea1f9eb6659f917d3bee3858a96542be2191eda3c7ccc7e0a388745c9d873a73aa021d950731fa1b65c14d38ae747ddff419bb0a7b9fe4e472ad3cfb62ce21c7e458672ac076a0d281c1e06ba409f0d3d80ebb80ddb79beb0e8d379473789193f10ea8011f77e71a7342117979c7c6c5c2b512058ca9b36c98953fba8b0a6461b00dfca84eb355d8fb344751e57d429b81936984f9477f34adfadcaf02fcaafd4902c492d4ad839a5d1b5e3344b2051900000000280dd422345c76d15e4fe744650dd77d4b6534f450b7a0be8a492b871cbe8107967194a7c62740eae123fa7fd52466136805ac8a924bd5812e1cd371898374216bd1eef6e79f70224d3c163e44a328b69ff3ceaf7e0244bd6932576aee4362fcb")
	// vk.ReadFrom(bytes.NewReader(vkBytes))

	// buf.Reset()
	// fmt.Println("proof")
	// fmt.Println("_proof.Ar", _proof.Ar.X.String(), _proof.Ar.Y.String())
	// fmt.Println("_proof.Bs", _proof.Bs.X.A0.String(),
	// 	_proof.Bs.X.A1.String(),
	// 	_proof.Bs.Y.A0.String(),
	// 	_proof.Bs.X.A1.String())
	// fmt.Println("_proof.Krs", _proof.Krs.X.String(), _proof.Krs.Y.String())
	// fmt.Println("hash", publicHash)
	// fmt.Println("preImage", preImage)

	// before returning verifies that the proof passes on bls12377
	if err := groth16_bls12377.Verify(proof, vk, publicWitness); err != nil {
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
	var innerVk groth16_bls12377.VerifyingKey
	var innerProof groth16_bls12377.Proof
	generateBls12377InnerProof(t, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1.K = make([]sw_bls12377.G1Affine, len(innerVk.G1.K))

	// create assignment, the private part consists of the proof,
	// the public part is exactly the public part of the inner proof,
	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
	var witness verifierCircuit
	witness.InnerProof.Ar.Assign(&innerProof.Ar)
	witness.InnerProof.Krs.Assign(&innerProof.Krs)
	witness.InnerProof.Bs.Assign(&innerProof.Bs)

	witness.InnerVk.Assign(&innerVk)
	witness.Hash = publicHash

	// verifies the cs
	assert := test.NewAssert(t)

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

	/* comment from here */

	// TODO uncommenting the lines below yield incredibly long testing time (due to the setup)
	// generate groth16 instance on bw6761 (setup, prove, verify)
	// var vk groth16_bw6761.VerifyingKey
	// var pk groth16_bw6761.ProvingKey

	// groth16_bw6761.Setup(&r1cs, &pk, &vk)
	// proof, err := groth16_bw6761.Prove(&r1cs, &pk, correctAssignment)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// res, err := groth16_bw6761.Verify(proof, &vk, correctAssignment)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// if !res {
	// 	t.Fatal("correct proof should pass")
	// }

}

func BenchmarkCompile(b *testing.B) {
	// get the data
	var innerVk groth16_bls12377.VerifyingKey
	var innerProof groth16_bls12377.Proof
	generateBls12377InnerProof(nil, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1.K = make([]sw_bls12377.G1Affine, len(innerVk.G1.K))

	var ccs frontend.CompiledConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, _ = frontend.Compile(ecc.BW6_761, r1cs.NewBuilder, &circuit)
	}
	b.Log(ccs.GetNbConstraints())
}

//--------------------------------------------------------------------
// bench

// TODO fixme
// func BenchmarkVerifier(b *testing.B) {

// 	// get the data
// 	var innerVk groth16_bls12377.VerifyingKey
// 	var innerProof groth16_bls12377.Proof
// 	inputNamesInnerProof := generateBls12377InnerProof(nil, &innerVk, &innerProof) // get public inputs of the inner proof

// 	// create an empty cs
// 	var circuit XXXX
// 	r1cs, err := compiler.Compile(gurvy.XXXX, &circuit)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// pairing data
// 	var pairingInfo sw_bls12377.PairingContext
// 	pairingInfo.Extension = fields_bls12377.GetBLS12377ExtensionFp12(&gnark)
// 	pairingInfo.AteLoop = 9586122913090633729

// 	// allocate the verifying key
// 	var innerVkCircuit VerifyingKey
// 	allocateInnerVk(&cs, &innerVk, &innerVkCircuit)

// 	// create secret inputs corresponding to the proof
// 	var innerProofCircuit Proof
// 	allocateInnerProof(&cs, &innerProofCircuit)

// 	// create the verifier cs
// 	Verify(&cs, pairingInfo, innerVkCircuit, innerProofCircuit, inputNamesInnerProof)

// 	// create r1cs
// 	r1cs := api.ToR1CS().ToR1CS(ecc.BW6_761)

// 	// create assignment, the private part consists of the proof,
// 	// the public part is exactly the public part of the inner proof,
// 	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
// 	correctAssignment := make(map[string]interface{})
// 	assignPointAffineG1(correctAssignment, innerProof.Ar, "Ar")
// 	assignPointAffineG1(correctAssignment, innerProof.Krs, "Krs")
// 	assignPointAffineG2(correctAssignment, innerProof.Bs, "Bs")
// 	correctAssignment["public_hash"] = publicHash

// 	// verifies the cs
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		r1cs.Inspect(correctAssignment, false)
// 	}

// }

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
