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
	eddsa_bn256 "github.com/consensys/gnark/cryptolib/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	twistededwards_gadget "github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
	twistededwards_bn256 "github.com/consensys/gurvy/bn256/twistededwards"
)

func TestEddsaGadget(t *testing.T) {

	assert := groth16_bn256.NewAssert(t)

	params := twistededwards_bn256.GetEdwardsCurve()

	var seed [32]byte
	s := []byte("eddsa")
	for i, v := range s {
		seed[i] = v
	}

	// create eddsa obj and sign a message
	signer := eddsa_bn256.New(seed, params)
	var msg fr_bn256.Element
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")
	signature, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := eddsa_bn256.Verify(signature, msg, signer.Pub, &params)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifying the signature should return true")
	}

	// Set the eddsa circuit and the gadget
	circuit := frontend.New()

	paramsGadget, err := twistededwards_gadget.NewEdCurveGadget(&circuit, gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// Allocate the data in the circuit
	var pubKeyAllocated PublicKeyGadget
	pubKeyAllocated.A.X = circuit.PUBLIC_INPUT("pubkeyX")
	pubKeyAllocated.A.Y = circuit.PUBLIC_INPUT("pubkeyY")

	var sigAllocated SignatureGadget
	sigAllocated.R.A.X = circuit.PUBLIC_INPUT("sigRX")
	sigAllocated.R.A.Y = circuit.PUBLIC_INPUT("sigRY")

	sigAllocated.S = circuit.PUBLIC_INPUT("sigS")

	msgAllocated := circuit.PUBLIC_INPUT("message")

	// verify the signature in the circuit
	Verify(&circuit, sigAllocated, msgAllocated, pubKeyAllocated, paramsGadget)

	// verification with the correct message
	good := backend.NewAssignment()
	good.Assign(backend.Public, "message", msg)

	good.Assign(backend.Public, "pubkeyX", signer.Pub.A.X)
	good.Assign(backend.Public, "pubkeyY", signer.Pub.A.Y)

	good.Assign(backend.Public, "sigRX", signature.R.X)
	good.Assign(backend.Public, "sigRY", signature.R.Y)

	var SMont fr_bn256.Element
	SMont.Set(&signature.S).ToMont()
	good.Assign(backend.Public, "sigS", SMont)

	_r1cs := circuit.ToR1CS()
	r1cs := backend_bn256.New(_r1cs)

	assert.CorrectExecution(&r1cs, good, nil)

	// verification with incorrect message
	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "message", "44717650746155748460101257525078853138837311576962212923649547644148297035979")

	bad.Assign(backend.Public, "pubkeyX", signer.Pub.A.X)
	bad.Assign(backend.Public, "pubkeyY", signer.Pub.A.Y)

	bad.Assign(backend.Public, "sigRX", signature.R.X)
	bad.Assign(backend.Public, "sigRY", signature.R.Y)

	bad.Assign(backend.Public, "sigS", SMont)
	assert.NotSolved(&r1cs, bad)
}
