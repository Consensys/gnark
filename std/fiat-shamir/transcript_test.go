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

package fiatshamir

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type FiatShamirCircuit struct {
	Bindings   [3][4]frontend.Variable `gnark:",public"`
	Challenges [3]frontend.Variable    `gnark:",secret"`
}

func (circuit *FiatShamirCircuit) Define(api frontend.API) error {

	// create the hash function
	hSnark, err := mimc.NewMiMC("seed", api)
	if err != nil {
		return err
	}

	// get the challenges
	alpha, beta, gamma := getChallenges(api.Curve())

	// New transcript with 3 challenges to be derived
	tsSnark := NewTranscript(api, &hSnark, alpha, beta, gamma)

	// Bind challenges
	tsSnark.Bind(alpha, circuit.Bindings[0][:])
	tsSnark.Bind(beta, circuit.Bindings[1][:])
	tsSnark.Bind(gamma, circuit.Bindings[2][:])

	// derive challenges
	var challenges [3]frontend.Variable
	challenges[0], err = tsSnark.ComputeChallenge(alpha)
	if err != nil {
		return err
	}

	challenges[1], err = tsSnark.ComputeChallenge(beta)
	if err != nil {
		return err
	}
	challenges[2], err = tsSnark.ComputeChallenge(gamma)
	if err != nil {
		return err
	}

	// // check equality between expected values
	api.AssertIsEqual(challenges[0], circuit.Challenges[0])
	api.AssertIsEqual(challenges[1], circuit.Challenges[1])
	api.AssertIsEqual(challenges[2], circuit.Challenges[2])

	return nil
}

func getChallenges(curveID ecc.ID) (string, string, string) {
	// note: gnark-crypto fiat-shamir is curve-independent ->
	// it writes the domain separators as bytes
	// in gnark, we write them as field element
	// to ensure consistency in this test, we ensure the challengeIDs have a fix byte len (the one of fr.Element)
	frSize := curveID.Info().Fr.Bytes
	alpha, beta, gamma := make([]byte, frSize), make([]byte, frSize), make([]byte, frSize)
	alpha[0] = 0xde
	beta[0] = 0xad
	gamma[0] = 0xf0

	return string(alpha), string(beta), string(gamma)
}

func TestFiatShamir(t *testing.T) {
	assert := test.NewAssert(t)

	testData := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BW6_633:   hash.MIMC_BW6_633,
	}

	// compute the witness for each curve
	for curveID, h := range testData {
		// get the domain separators, correctly formatted so they match the frontend.Variable size
		// (which under the hood is a fr.Element)
		alpha, beta, gamma := getChallenges(curveID)

		// instantiate the hash and the transcript in plain go
		ts := fiatshamir.NewTranscript(h.New("seed"), alpha, beta, gamma)

		var bindings [3][4]big.Int
		for i := 0; i < 3; i++ {
			for j := 0; j < 4; j++ {
				bindings[i][j].SetUint64(uint64(i * j))
			}
		}
		buf := make([]byte, curveID.Info().Fr.Bytes)
		for i := 0; i < 4; i++ {
			ts.Bind(alpha, bindings[0][i].FillBytes(buf))
			ts.Bind(beta, bindings[1][i].FillBytes(buf))
			ts.Bind(gamma, bindings[2][i].FillBytes(buf))
		}

		var expectedChallenges [3][]byte
		var err error
		expectedChallenges[0], err = ts.ComputeChallenge(alpha)
		assert.NoError(err)
		expectedChallenges[1], err = ts.ComputeChallenge(beta)
		assert.NoError(err)
		expectedChallenges[2], err = ts.ComputeChallenge(gamma)
		assert.NoError(err)

		// instantiate the circuit with provided inputs
		var witness FiatShamirCircuit

		for i := 0; i < 3; i++ {
			for j := 0; j < 4; j++ {
				witness.Bindings[i][j] = bindings[i][j]
			}
			witness.Challenges[i] = expectedChallenges[i]
		}

		assert.SolvingSucceeded(&FiatShamirCircuit{}, &witness, test.WithCurves(curveID))
	}

}

func BenchmarkCompile(b *testing.B) {
	// create an empty cs
	var circuit FiatShamirCircuit

	var ccs compiled.CompiledConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, _ = frontend.Compile(ecc.BN254, backend.PLONK, &circuit)
	}
	b.Log(ccs.GetNbConstraints())
}
