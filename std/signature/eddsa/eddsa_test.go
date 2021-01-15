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
	"github.com/consensys/gnark/crypto/hash"
	"github.com/consensys/gnark/crypto/signature"
	eddsabls377 "github.com/consensys/gnark/crypto/signature/eddsa/bls377"
	eddsabls381 "github.com/consensys/gnark/crypto/signature/eddsa/bls381"
	eddsabn256 "github.com/consensys/gnark/crypto/signature/eddsa/bn256"
	eddsabw761 "github.com/consensys/gnark/crypto/signature/eddsa/bw761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gurvy"
)

type eddsaCircuit struct {
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func parseSignature(id gurvy.ID, buf []byte) ([]byte, []byte, []byte) {
	var sizeFr int
	switch id {
	case gurvy.BN256:
		sizeFr = 32
	case gurvy.BLS381:
		sizeFr = 32
	case gurvy.BLS377:
		sizeFr = 32
	case gurvy.BW761:
		sizeFr = 48
	}
	return buf[:sizeFr], buf[sizeFr : 2*sizeFr], buf[2*sizeFr:]
}

func parsePublicKey(id gurvy.ID, buf []byte) ([]byte, []byte) {
	var sizeFr int
	switch id {
	case gurvy.BN256:
		sizeFr = 32
	case gurvy.BLS381:
		sizeFr = 32
	case gurvy.BLS377:
		sizeFr = 32
	case gurvy.BW761:
		sizeFr = 48
	}
	return buf[:sizeFr], buf[sizeFr:]
}

func (circuit *eddsaCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {

	params, err := twistededwards.NewEdCurve(curveID)
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

	type confSig struct {
		h hash.Hash
		s signature.SignatureScheme
	}

	signature.Register(signature.EDDSA_BN256, eddsabn256.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS381, eddsabls381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS377, eddsabls377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW761, eddsabw761.GenerateKeyInterfaces)

	confs := map[gurvy.ID]confSig{
		gurvy.BN256:  {hash.MIMC_BN256, signature.EDDSA_BN256},
		gurvy.BLS381: {hash.MIMC_BLS381, signature.EDDSA_BLS381},
		gurvy.BLS377: {hash.MIMC_BLS377, signature.EDDSA_BLS377},
		gurvy.BW761:  {hash.MIMC_BW761, signature.EDDSA_BW761},
	}
	for id, conf := range confs {

		// generate parameters for the signatures
		hFunc := conf.h.New("seed")
		pubKey, privKey := conf.s.New(seed)

		// pick a message to sign
		var frMsg big.Int
		frMsg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978", 10)
		msgBin := frMsg.Bytes()

		// generate signature
		signature, err := privKey.Sign(msgBin[:], hFunc)
		if err != nil {
			t.Fatal(err)
		}

		// check if there is no problem in the signature
		checkSig, err := pubKey.Verify(signature, msgBin[:], hFunc)
		if err != nil {
			t.Fatal(err)
		}
		if !checkSig {
			t.Fatal("Unexpected failed signature verification")
		}

		// create and compile the circuit for signature verification
		var circuit eddsaCircuit
		r1cs, err := frontend.Compile(id, &circuit)
		if err != nil {
			t.Fatal(err)
		}

		// verification with the correct Message
		{
			var witness eddsaCircuit
			witness.Message.Assign(frMsg)

			pubkeyAx, pubkeyAy := parsePublicKey(id, pubKey.Bytes())
			var pbAx, pbAy big.Int
			pbAx.SetBytes(pubkeyAx)
			pbAy.SetBytes(pubkeyAy)
			witness.PublicKey.A.X.Assign(pubkeyAx)
			witness.PublicKey.A.Y.Assign(pubkeyAy)

			sigRx, sigRy, sigS := parseSignature(id, signature)
			witness.Signature.R.A.X.Assign(sigRx)
			witness.Signature.R.A.Y.Assign(sigRy)
			witness.Signature.S.Assign(sigS)

			assert.SolvingSucceeded(r1cs, &witness)
		}

		// verification with incorrect Message
		{
			var witness eddsaCircuit
			witness.Message.Assign("44717650746155748460101257525078853138837311576962212923649547644148297035979")

			pubkeyAx, pubkeyAy := parsePublicKey(id, pubKey.Bytes())
			witness.PublicKey.A.X.Assign(pubkeyAx)
			witness.PublicKey.A.Y.Assign(pubkeyAy)

			sigRx, sigRy, sigS := parseSignature(id, signature)
			witness.Signature.R.A.X.Assign(sigRx)
			witness.Signature.R.A.Y.Assign(sigRy)
			witness.Signature.S.Assign(sigS)

			assert.SolvingFailed(r1cs, &witness)
		}

	}
}
