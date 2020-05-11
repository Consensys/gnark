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

	"github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	groth16_bn256 "github.com/consensys/gnark/backend/bn256/groth16"
	mimc_bn256 "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	eddsa_bn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	twistededwards_gadget "github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

func TestEddsaGadget(t *testing.T) {

	assert := groth16_bn256.NewAssert(t)

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

	paramsGadget, err := twistededwards_gadget.NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// Allocate the data in the circuit
	var pubKeyAllocated PublicKeyGadget
	pubKeyAllocated.A.X = circuit.PUBLIC_INPUT("pubkeyX")
	pubKeyAllocated.A.Y = circuit.PUBLIC_INPUT("pubkeyY")
	pubKeyAllocated.Curve = paramsGadget

	var sigAllocated SignatureGadget
	sigAllocated.R.A.X = circuit.PUBLIC_INPUT("sigRX")
	sigAllocated.R.A.Y = circuit.PUBLIC_INPUT("sigRY")

	sigAllocated.S = circuit.PUBLIC_INPUT("sigS")

	msgAllocated := circuit.PUBLIC_INPUT("message")

	// verify the signature in the circuit
	Verify(&circuit, sigAllocated, msgAllocated, pubKeyAllocated)

	// verification with the correct message
	good := backend.NewAssignment()
	good.Assign(backend.Public, "message", msg)

	good.Assign(backend.Public, "pubkeyX", pubKey.A.X)
	good.Assign(backend.Public, "pubkeyY", pubKey.A.Y)

	good.Assign(backend.Public, "sigRX", signature.R.X)
	good.Assign(backend.Public, "sigRY", signature.R.Y)

	good.Assign(backend.Public, "sigS", signature.S)

	r1cs := backend_bn256.New(&circuit)

	assert.CorrectExecution(&r1cs, good, nil)

	// verification with incorrect message
	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "message", "44717650746155748460101257525078853138837311576962212923649547644148297035979")

	bad.Assign(backend.Public, "pubkeyX", pubKey.A.X)
	bad.Assign(backend.Public, "pubkeyY", pubKey.A.Y)

	bad.Assign(backend.Public, "sigRX", signature.R.X)
	bad.Assign(backend.Public, "sigRY", signature.R.Y)

	bad.Assign(backend.Public, "sigS", signature.S)
	assert.NotSolved(&r1cs, bad)
}
