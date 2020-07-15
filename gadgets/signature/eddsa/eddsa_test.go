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

func TestEddsa(t *testing.T) {

	assert := groth16.NewAssert(t)

	var seed [32]byte
	s := []byte("eddsa")
	for i, v := range s {
		seed[i] = v
	}

	hFunc := mimc_bn256.NewMiMC("seed")

	// create eddsa obj and sign a message
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

	// Set the eddsa circuit and the gadget
	circuit := frontend.New()

	params, err := twistededwards.NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// Allocate the data in the circuit
	var pubKeyAllocated PublicKey
	pubKeyAllocated.A.X = circuit.PUBLIC_INPUT("pubkeyX")
	pubKeyAllocated.A.Y = circuit.PUBLIC_INPUT("pubkeyY")
	pubKeyAllocated.Curve = params

	var sigAllocated Signature
	sigAllocated.R.A.X = circuit.PUBLIC_INPUT("sigRX")
	sigAllocated.R.A.Y = circuit.PUBLIC_INPUT("sigRY")

	sigAllocated.S = circuit.PUBLIC_INPUT("sigS")

	msgAllocated := circuit.PUBLIC_INPUT("message")

	// verify the signature in the circuit
	Verify(&circuit, sigAllocated, msgAllocated, pubKeyAllocated)

	// verification with the correct message
	good := make(map[string]interface{})
	good["message"] = msg

	good["pubkeyX"] = pubKey.A.X
	good["pubkeyY"] = pubKey.A.Y

	good["sigRX"] = signature.R.X
	good["sigRY"] = signature.R.Y

	good["sigS"] = signature.S

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assert.CorrectExecution(r1cs, good, nil)

	// verification with incorrect message
	bad := make(map[string]interface{})
	bad["message"] = "44717650746155748460101257525078853138837311576962212923649547644148297035979"

	bad["pubkeyX"] = pubKey.A.X
	bad["pubkeyY"] = pubKey.A.Y

	bad["sigRX"] = signature.R.X
	bad["sigRY"] = signature.R.Y

	bad["sigS"] = signature.S
	assert.NotSolved(r1cs, bad)
}
