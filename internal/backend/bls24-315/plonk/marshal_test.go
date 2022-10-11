// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package plonk

import (
	curve "github.com/nume-crypto/gnark-crypto/ecc/bls24-315"

	"github.com/nume-crypto/gnark-crypto/ecc/bls24-315/fr"

	"bytes"
	"github.com/nume-crypto/gnark-crypto/ecc/bls24-315/fr/fft"
	gnarkio "github.com/consensys/gnark/io"
	"io"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

func TestProofSerialization(t *testing.T) {
	// create a  proof
	var proof, reconstructed Proof
	proof.randomize()

	roundTripCheck(t, &proof, &reconstructed)
}

func TestProofSerializationRaw(t *testing.T) {
	// create a  proof
	var proof, reconstructed Proof
	proof.randomize()

	roundTripCheckRaw(t, &proof, &reconstructed)
}

func TestProvingKeySerialization(t *testing.T) {
	// random pk
	var pk, reconstructed ProvingKey
	pk.randomize()

	roundTripCheck(t, &pk, &reconstructed)
}

func TestVerifyingKeySerialization(t *testing.T) {
	// create a random vk
	var vk, reconstructed VerifyingKey
	vk.randomize()

	roundTripCheck(t, &vk, &reconstructed)
}

func roundTripCheck(t *testing.T, from io.WriterTo, reconstructed io.ReaderFrom) {
	var buf bytes.Buffer
	written, err := from.WriteTo(&buf)
	if err != nil {
		t.Fatal("coudln't serialize", err)
	}

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("coudln't deserialize", err)
	}

	if !reflect.DeepEqual(from, reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}

func roundTripCheckRaw(t *testing.T, from gnarkio.WriterRawTo, reconstructed io.ReaderFrom) {
	var buf bytes.Buffer
	written, err := from.WriteRawTo(&buf)
	if err != nil {
		t.Fatal("coudln't serialize", err)
	}

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("coudln't deserialize", err)
	}

	if !reflect.DeepEqual(from, reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}

func (pk *ProvingKey) randomize() {
	var vk VerifyingKey
	vk.randomize()
	pk.Vk = &vk
	pk.Domain[0] = *fft.NewDomain(42)
	pk.Domain[1] = *fft.NewDomain(4 * 42)

	n := int(pk.Domain[0].Cardinality)
	pk.Ql = randomScalars(n)
	pk.Qr = randomScalars(n)
	pk.Qm = randomScalars(n)
	pk.Qo = randomScalars(n)
	pk.CQk = randomScalars(n)
	pk.LQk = randomScalars(n)
	pk.S1Canonical = randomScalars(n)
	pk.S2Canonical = randomScalars(n)
	pk.S3Canonical = randomScalars(n)
	pk.EvaluationPermutationBigDomainBitReversed = randomScalars(n)

	pk.Permutation = make([]int64, 3*pk.Domain[0].Cardinality)
	pk.Permutation[0] = -12
	pk.Permutation[len(pk.Permutation)-1] = 8888
}

func (vk *VerifyingKey) randomize() {
	vk.Size = rand.Uint64()
	vk.SizeInv.SetRandom()
	vk.Generator.SetRandom()
	vk.NbPublicVariables = rand.Uint64()
	vk.CosetShift.SetRandom()

	vk.S[0] = randomPoint()
	vk.S[1] = randomPoint()
	vk.S[2] = randomPoint()
	vk.Ql = randomPoint()
	vk.Qr = randomPoint()
	vk.Qm = randomPoint()
	vk.Qo = randomPoint()
	vk.Qk = randomPoint()
}

func (proof *Proof) randomize() {
	proof.LRO[0] = randomPoint()
	proof.LRO[1] = randomPoint()
	proof.LRO[2] = randomPoint()
	proof.Z = randomPoint()
	proof.H[0] = randomPoint()
	proof.H[1] = randomPoint()
	proof.H[2] = randomPoint()
	proof.BatchedProof.H = randomPoint()
	proof.BatchedProof.ClaimedValues = randomScalars(2)
	proof.ZShiftedOpening.H = randomPoint()
	proof.ZShiftedOpening.ClaimedValue.SetRandom()
}

func randomPoint() curve.G1Affine {
	_, _, r, _ := curve.Generators()
	r.ScalarMultiplication(&r, big.NewInt(int64(rand.Uint64())))
	return r
}

func randomScalars(n int) []fr.Element {
	v := make([]fr.Element, n)
	one := fr.One()
	for i := 0; i < len(v); i++ {
		if i == 0 {
			v[i].SetRandom()
		} else {
			v[i].Add(&v[i-1], &one)
		}
	}
	return v
}
