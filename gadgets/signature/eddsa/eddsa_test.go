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

package eddsa

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	mimc_bn256 "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	eddsa_bn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

type eddsaCircuit struct {
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	params, err := twistededwards.NewEdCurve(gurvy.BN256)
	if err != nil {
		return err
	}
	circuit.PublicKey.Curve = params

	// verify the signature in the cs
	Verify(cs, circuit.Signature, circuit.Message, circuit.PublicKey)

	return nil
}

func TestEddsa(t *testing.T) {

	assert := groth16.NewAssert(t)

	var seed [32]byte
	s := []byte("eddsa")
	for i, v := range s {
		seed[i] = v
	}

	hFunc := mimc_bn256.NewMiMC("seed")

	// create eddsa obj and sign a Message
	pubKey, privKey := eddsa_bn256.New(seed, hFunc)
	var msg fr_bn256.Element
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")
	signature, err := eddsa_bn256.Sign(msg, pubKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	res, err := eddsa_bn256.Verify(signature, msg, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifying the signature should return true")
	}

	// Set the eddsa cs and the gadget
	var circuit eddsaCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// verification with the correct Message
	good := make(map[string]interface{})
	good["Message"] = msg

	good["PublicKey_A_X"] = pubKey.A.X
	good["PublicKey_A_Y"] = pubKey.A.Y

	good["Signature_R_A_X"] = signature.R.X
	good["Signature_R_A_Y"] = signature.R.Y

	good["Signature_S"] = signature.S

	assert.CorrectExecution(r1cs, good, nil)

	// verification with incorrect Message
	bad := make(map[string]interface{})
	bad["Message"] = "44717650746155748460101257525078853138837311576962212923649547644148297035979"

	bad["PublicKey_A_X"] = pubKey.A.X
	bad["PublicKey_A_Y"] = pubKey.A.Y

	bad["Signature_R_A_X"] = signature.R.X
	bad["Signature_R_A_Y"] = signature.R.Y

	bad["Signature_S"] = signature.S
	assert.NotSolved(r1cs, bad)
}
