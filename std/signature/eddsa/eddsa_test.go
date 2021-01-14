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
	"math/big"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	mimc_bn256 "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	eddsa_bn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

type eddsaCircuit struct {
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
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

	// generate eddsa witnesses from the crypto lib
	pubKey, privKey := eddsa_bn256.GenerateKey(seed)

	var frMsg fr_bn256.Element
	frMsg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")
	msgBin := frMsg.Bytes()
	signature, err := eddsa_bn256.Sign(msgBin[:], &privKey, hFunc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := eddsa_bn256.Verify(signature, msgBin[:], &pubKey, hFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifying the signature should return true")
	}

	var circuit eddsaCircuit
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// verification with the correct Message
	{
		var witness eddsaCircuit
		witness.Message.Assign(frMsg)

		witness.PublicKey.A.X.Assign(pubKey.A.X)
		witness.PublicKey.A.Y.Assign(pubKey.A.Y)

		witness.Signature.R.A.X.Assign(signature.R.X)
		witness.Signature.R.A.Y.Assign(signature.R.Y)

		var bs big.Int
		bs.SetBytes(signature.S[:])
		witness.Signature.S.Assign(bs)

		assert.SolvingSucceeded(r1cs, &witness)
	}

	// verification with incorrect Message
	{
		var witness eddsaCircuit
		witness.Message.Assign("44717650746155748460101257525078853138837311576962212923649547644148297035979")

		witness.PublicKey.A.X.Assign(pubKey.A.X)
		witness.PublicKey.A.Y.Assign(pubKey.A.Y)

		witness.Signature.R.A.X.Assign(signature.R.X)
		witness.Signature.R.A.Y.Assign(signature.R.Y)

		var bs big.Int
		bs.SetBytes(signature.S[:])
		witness.Signature.S.Assign(bs)

		assert.SolvingFailed(r1cs, &witness)
	}
}
