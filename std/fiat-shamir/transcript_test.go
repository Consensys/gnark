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
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type FiatShamirCircuit struct {
	Bindings   [3][4]frontend.Variable `gnark:",public"`
	Challenges [3]frontend.Variable    `gnark:",secret"`
}

func (circuit *FiatShamirCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// create the hash function
	hSnark, err := mimc.NewMiMC("seed", ecc.BN254, cs)
	if err != nil {
		return err
	}

	// get the challenges
	alpha, beta, gamma := getChallenges()

	// New transcript with 3 challenges to be derived
	tsSnark := NewTranscript(cs, &hSnark, alpha, beta, gamma)

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
	cs.AssertIsEqual(challenges[0], circuit.Challenges[0])
	cs.AssertIsEqual(challenges[1], circuit.Challenges[1])
	cs.AssertIsEqual(challenges[2], circuit.Challenges[2])

	return nil
}

func getChallenges() (string, string, string) {

	// domain separators: we make sure they fit in fr.Element size
	var _alpha, _beta, _gamma fr.Element
	_alpha.SetString("198719831987198319871983198719831987198319871983198719")
	_beta.SetString("893782372892325372635723577392832973")
	_gamma.SetString("98392387236276287638276382728082")

	alpha := string(_alpha.Marshal())
	beta := string(_beta.Marshal())
	gamma := string(_gamma.Marshal())

	return alpha, beta, gamma
}

func TestFiatShamir(t *testing.T) {

	// get the domain separators, correctly formatted so they match the frontend.Variable size
	// (which under the hood is a fr.Element)
	alpha, beta, gamma := getChallenges()

	// instantiate the hash and the transcript in plain go
	h := hash.MIMC_BN254.New("seed")
	ts := fiatshamir.NewTranscript(h, alpha, beta, gamma)

	var bindings [3][4]fr.Element
	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			bindings[i][j].SetRandom()
		}
	}
	for i := 0; i < 4; i++ {
		ts.Bind(alpha, bindings[0][i].Marshal())
		ts.Bind(beta, bindings[1][i].Marshal())
		ts.Bind(gamma, bindings[2][i].Marshal())
	}

	var expectedChallenges [3][]byte
	var err error
	expectedChallenges[0], err = ts.ComputeChallenge(alpha)
	if err != nil {
		t.Fatal(err)
	}
	expectedChallenges[1], err = ts.ComputeChallenge(beta)
	if err != nil {
		t.Fatal(err)
	}
	expectedChallenges[2], err = ts.ComputeChallenge(gamma)
	if err != nil {
		t.Fatal(err)
	}

	// instantiate the circuit with provided inputs
	var circuit, witness FiatShamirCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			witness.Bindings[i][j].Assign(bindings[i][j])
		}
		witness.Challenges[i].Assign(expectedChallenges[i])
	}
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}
