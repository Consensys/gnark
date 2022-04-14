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

package kzg_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type verifierCircuit struct {
	VerifKey VK
	Proof    OpeningProof
	Com      Digest
	S        Point
}

func (circuit *verifierCircuit) Define(api frontend.API) error {

	// create the verifier cs
	Verify(api, circuit.Com, circuit.Proof, circuit.S, circuit.VerifKey)

	return nil
}

func TestVerifier(t *testing.T) {

	var circuit, witness verifierCircuit

	// create a polynomial
	f := randomPolynomial(60)

	// commit the polynomial
	digest, err := kzg_bls12377.Commit(f, testSRS)
	if err != nil {
		t.Fatal(err)
	}

	// compute opening proof at a random point
	var point fr.Element
	point.SetString("4321")
	proof, err := kzg_bls12377.Open(f, point, testSRS)
	if err != nil {
		t.Fatal(err)
	}

	// verify the claimed valued
	expected := eval(f, point)
	if !proof.ClaimedValue.Equal(&expected) {
		t.Fatal("inconsistant claimed value")
	}

	witness.Proof.H.Assign(&proof.H)
	witness.Proof.ClaimedValue = proof.ClaimedValue
	witness.Com.Assign(&digest)
	witness.S = point
	witness.VerifKey.G1.Assign(&testSRS.G1[0])
	witness.VerifKey.G2[0].Assign(&testSRS.G2[0])
	witness.VerifKey.G2[1].Assign(&testSRS.G2[1])

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// utils
// testSRS re-used accross tests of the KZG scheme
var testSRS *kzg_bls12377.SRS

func init() {
	const srsSize = 230
	testSRS, _ = kzg_bls12377.NewSRS(ecc.NextPowerOfTwo(srsSize), new(big.Int).SetInt64(42))
}

// samples a random polynomial
func randomPolynomial(size int) []fr.Element {
	f := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		f[i].SetRandom()
	}
	return f
}

// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}
