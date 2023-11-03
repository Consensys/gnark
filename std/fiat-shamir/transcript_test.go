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
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
	"golang.org/x/exp/slices"
)

//------------------------------------------------------
// bitMode==false

type FiatShamirCircuit struct {
	Bindings   [3][4]frontend.Variable `gnark:",public"`
	Challenges [3]frontend.Variable    `gnark:",secret"`
}

func (circuit *FiatShamirCircuit) Define(api frontend.API) error {

	// create the hash function
	hSnark, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// New transcript with 3 challenges to be derived
	tsSnark := NewTranscript(api, &hSnark, "alpha", "beta", "gamma")

	// Bind challenges
	if err := tsSnark.Bind("alpha", circuit.Bindings[0][:]); err != nil {
		return err
	}
	if err := tsSnark.Bind("beta", circuit.Bindings[1][:]); err != nil {
		return err
	}
	if err := tsSnark.Bind("gamma", circuit.Bindings[2][:]); err != nil {
		return err
	}

	// derive challenges
	var challenges [3]frontend.Variable
	challenges[0], err = tsSnark.ComputeChallenge("alpha", false)
	if err != nil {
		return err
	}

	challenges[1], err = tsSnark.ComputeChallenge("beta", false)
	if err != nil {
		return err
	}
	challenges[2], err = tsSnark.ComputeChallenge("gamma", false)
	if err != nil {
		return err
	}

	// // check equality between expected values
	api.AssertIsEqual(challenges[0], circuit.Challenges[0])
	api.AssertIsEqual(challenges[1], circuit.Challenges[1])
	api.AssertIsEqual(challenges[2], circuit.Challenges[2])

	return nil
}

func TestFiatShamir(t *testing.T) {
	assert := test.NewAssert(t)

	testData := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
		ecc.BLS24_317: hash.MIMC_BLS24_317,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BW6_633:   hash.MIMC_BW6_633,
	}

	// compute the witness for each curve
	for curveID, h := range testData {

		// instantiate the hash and the transcript in plain go
		ts := fiatshamir.NewTranscript(h.New(), "alpha", "beta", "gamma")

		var bindings [3][4]big.Int
		for i := 0; i < 3; i++ {
			for j := 0; j < 4; j++ {
				bindings[i][j].SetUint64(uint64(i * j))
			}
		}
		frSize := utils.ByteLen(curveID.ScalarField())
		buf := make([]byte, frSize)
		for i := 0; i < 4; i++ {
			err := ts.Bind("alpha", bindings[0][i].FillBytes(buf))
			assert.NoError(err)
			err = ts.Bind("beta", bindings[1][i].FillBytes(buf))
			assert.NoError(err)
			err = ts.Bind("gamma", bindings[2][i].FillBytes(buf))
			assert.NoError(err)
		}

		var expectedChallenges [3][]byte
		var err error
		expectedChallenges[0], err = ts.ComputeChallenge("alpha")
		assert.NoError(err)
		expectedChallenges[1], err = ts.ComputeChallenge("beta")
		assert.NoError(err)
		expectedChallenges[2], err = ts.ComputeChallenge("gamma")
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

//------------------------------------------------------
// bitMode==true

type FiatShamirCircuitBitMode struct {
	Bindings  [2][4]frontend.Variable
	Challenge [2]frontend.Variable
}

func (circuit *FiatShamirCircuitBitMode) Define(api frontend.API) error {

	// pick a number on byte shorter than the modulus size
	var target big.Int
	target.SetUint64(1)
	nbBits := api.Compiler().Field().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))

	// create the wrapped hash function
	whSnark, err := recursion.NewHash(api, &target, true)
	if err != nil {
		return err
	}

	// New transcript with 3 challenges to be derived
	tsSnark := NewTranscript(api, whSnark, "alpha", "beta")
	challengesNames := []string{"alpha", "beta"}

	nbBitsFull := ((api.Compiler().Field().BitLen() + 7) / 8) * 8
	for j := 0; j < 2; j++ {
		for i := 0; i < 4; i++ {
			binBindings := api.ToBinary(circuit.Bindings[j][i], nbBitsFull)
			slices.Reverse(binBindings)
			err = tsSnark.Bind(challengesNames[j], binBindings)
			if err != nil {
				return err
			}
		}
	}

	var challenges [2]frontend.Variable
	for i := 0; i < 2; i++ {
		challenges[i], err = tsSnark.ComputeChallenge(challengesNames[i], true)
		if err != nil {
			return err
		}
	}

	api.Println(challenges[1])
	for i := 0; i < 2; i++ {
		api.AssertIsEqual(challenges[i], circuit.Challenge[i])
	}

	return nil
}

func TestFiatShamirBitMode(t *testing.T) {

	assert := test.NewAssert(t)

	testData := map[ecc.ID]hash.Hash{
		ecc.BN254:     hash.MIMC_BN254,
		ecc.BLS12_377: hash.MIMC_BLS12_377,
		ecc.BLS12_381: hash.MIMC_BLS12_381,
		ecc.BLS24_315: hash.MIMC_BLS24_315,
		ecc.BLS24_317: hash.MIMC_BLS24_317,
		ecc.BW6_761:   hash.MIMC_BW6_761,
		ecc.BW6_633:   hash.MIMC_BW6_633,
	}

	// compute the witness for each curve
	for curveID, _ := range testData {

		// instantiate the hash and the transcript in plain go
		nbBits := ((curveID.ScalarField().BitLen()+7)/8)*8 - 8
		target := big.NewInt(1)
		target.Lsh(target, uint(nbBits))
		wh, err := recursion.NewShort(curveID.ScalarField(), target)
		assert.NoError(err)

		ts := fiatshamir.NewTranscript(wh, "alpha", "beta")

		var bindings [2][4]big.Int
		for i := 0; i < 2; i++ {
			for j := 0; j < 4; j++ {
				bindings[i][j].SetUint64(uint64(i*i + j*j))
			}
		}

		frSize := utils.ByteLen(curveID.ScalarField())
		buf := make([]byte, frSize)
		challengesNames := []string{"alpha", "beta"}
		for j := 0; j < 2; j++ {
			for i := 0; i < 4; i++ {
				err := ts.Bind(challengesNames[j], bindings[j][i].FillBytes(buf))
				assert.NoError(err)
			}
		}

		var expectedChallenges [2][]byte
		for i := 0; i < 2; i++ {
			expectedChallenges[i], err = ts.ComputeChallenge(challengesNames[i])
			assert.NoError(err)
		}
		var a big.Int
		a.SetBytes(expectedChallenges[1])
		fmt.Println(a.String())

		// instantiate the circuit with provided inputs
		var witness FiatShamirCircuitBitMode

		for i := 0; i < 2; i++ {
			witness.Challenge[i] = expectedChallenges[i]
		}
		for j := 0; j < 2; j++ {
			for i := 0; i < 4; i++ {
				witness.Bindings[j][i] = bindings[j][i]
			}
		}
		assert.CheckCircuit(&FiatShamirCircuitBitMode{}, test.WithValidAssignment(&witness), test.WithCurves(curveID))
	}

}

//------------------------------------------------------
// benchmark

func BenchmarkCompile(b *testing.B) {
	// create an empty cs
	var circuit FiatShamirCircuit

	var ccs constraint.ConstraintSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	}
	b.Log(ccs.GetNbConstraints())
}
