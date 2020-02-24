// +build bls381 bn256

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

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/internal/curve"
	twistededwards "github.com/consensys/gnark/cs/std/reference/algebra/twisted_edwards"
	"github.com/consensys/gnark/cs/std/reference/signature/eddsa"
)

func TestEddsaGadget(t *testing.T) {
	t.Skip("wip")
	assert := cs.NewAssert(t)

	edcurve := twistededwards.GetEdwardsCurve()

	var seed [32]byte
	s := []byte("eddsa")
	for i, v := range s {
		seed[i] = v
	}

	// create eddsa key pair and generate the signature
	privKey, pubKey := eddsa.New(seed, edcurve)

	var msg curve.Element
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")

	signedMsg, err := eddsa.Sign(privKey, pubKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := eddsa.Verify(pubKey, signedMsg, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("verification should pass")
	}

	// verify the signature in the circuit
	circuit := cs.New()
	messageAllocated := circuit.SECRET_INPUT("message")
	Verify(&circuit, pubKey, signedMsg, messageAllocated)

	// verification with the correct message
	good := cs.NewAssignment()
	good.Assign(cs.Secret, "message", "44717650746155748460101257525078853138837311576962212923649547644148297035978")
	assert.Solved(circuit, good, nil)

	// verification with incorrect message
	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "message", "44717650746155748460101257525078853138837311576962212923649547644148297035979")
	assert.NotSolved(circuit, bad)
}
