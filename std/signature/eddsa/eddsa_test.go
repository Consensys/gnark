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
	"math/rand"
	"testing"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, tedwards.BN254},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381},
		// {hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{hash.MIMC_BLS12_377, tedwards.BLS12_377},
		{hash.MIMC_BW6_761, tedwards.BW6_761},
		{hash.MIMC_BLS24_315, tedwards.BLS24_315},
		{hash.MIMC_BLS24_317, tedwards.BLS24_317},
		{hash.MIMC_BW6_633, tedwards.BW6_633},
	}

	bound := 1 //5
	if testing.Short() {
		bound = 1
	}

	for i := 0; i < bound; i++ {
		seed := time.Now().Unix()
		t.Logf("setting seed in rand %d", seed)
		randomness := rand.New(rand.NewSource(seed)) //#nosec G404 -- This is a false positive

		for _, conf := range confs {

			snarkField, err := twistededwards.GetSnarkField(conf.curve)
			assert.NoError(err)
			snarkCurve := utils.FieldToCurve(snarkField)

			// generate parameters for the signatures
			privKey, err := eddsa.New(conf.curve, randomness)
			assert.NoError(err, "generating eddsa key pair")

			// pick a message to sign
			var msg big.Int
			msg.Rand(randomness, snarkField)
			t.Log("msg to sign", msg.String())
			//msgData := msg.Bytes()

			// generate signature
			signature, err := privKey.SignNum(msg, conf.hash.New())
			assert.NoError(err, "signing message")

			// check if there is no problem in the signature
			pubKey := privKey.Public()
			checkSig, err := pubKey.VerifyNum(signature, msg, conf.hash.New())
			assert.NoError(err, "verifying signature")
			assert.True(checkSig, "signature verification failed")

			// create and compile the circuit for signature verification
			var circuit eddsaCircuit
			circuit.curveID = conf.curve

			// verification with the correct Message
			{
				var witness eddsaCircuit
				witness.Message = msg
				witness.PublicKey.Assign(conf.curve, pubKey.Bytes())
				witness.Signature.Assign(conf.curve, signature)

				assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))
			}

			// verification with incorrect Message
			{
				var witness eddsaCircuit

				msg.Rand(randomness, snarkField)
				witness.Message = msg
				witness.PublicKey.Assign(conf.curve, pubKey.Bytes())
				witness.Signature.Assign(conf.curve, signature)

				assert.SolvingFailed(&circuit, &witness, test.WithCurves(snarkCurve))
			}

		}
	}

}
