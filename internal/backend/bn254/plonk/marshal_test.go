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

package plonk

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	gnarkio "github.com/consensys/gnark/io"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"

	"math/big"
	"math/rand"
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
	var pk, reconstructed ProvingKeyBis
	pk.randomize()

	roundTripCheck(t, &pk, &reconstructed)
}

func TestVerifyingKeySerialization(t *testing.T) {
	// create a random vk
	var vk, reconstructed VerifyingKeyBis
	vk.randomize()

	roundTripCheck(t, &vk, &reconstructed)
}

func roundTripCheck(t *testing.T, from io.WriterTo, reconstructed io.ReaderFrom) {
	var buf bytes.Buffer
	written, err := from.WriteTo(&buf)
	if err != nil {
		t.Fatal("couldn't serialize", err)
	}

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("couldn't deserialize", err)
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
		t.Fatal("couldn't serialize", err)
	}

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("couldn't deserialize", err)
	}

	if !reflect.DeepEqual(from, reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}

func (pk *ProvingKeyBis) randomize() {

	var vk VerifyingKeyBis
	vk.randomize()
	pk.Vk = &vk
	pk.Domain[0] = *fft.NewDomain(42)
	pk.Domain[1] = *fft.NewDomain(4 * 42)

	n := int(pk.Domain[0].Cardinality)
	ql := randomScalars(n)
	qr := randomScalars(n)
	qm := randomScalars(n)
	qo := randomScalars(n)
	qk := randomScalars(n)
	lqk := randomScalars(n)
	s1 := randomScalars(n)
	s2 := randomScalars(n)
	s3 := randomScalars(n)

	var trace PlonkTrace
	canReg := iop.Form{Basis: iop.Canonical, Layout: iop.Regular}
	trace.Ql = iop.NewPolynomial(&ql, canReg)
	trace.Qr = iop.NewPolynomial(&qr, canReg)
	trace.Qm = iop.NewPolynomial(&qm, canReg)
	trace.Qo = iop.NewPolynomial(&qo, canReg)
	trace.Qk = iop.NewPolynomial(&qk, canReg)
	trace.S1 = iop.NewPolynomial(&s1, canReg)
	trace.S2 = iop.NewPolynomial(&s2, canReg)
	trace.S3 = iop.NewPolynomial(&s3, canReg)

	trace.S = make([]int64, 3*pk.Domain[0].Cardinality)
	trace.S[0] = -12
	trace.S[len(trace.S)-1] = 8888

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	pk.lQk = iop.NewPolynomial(&lqk, lagReg)

	pk.computeLagrangeCosetPolys()
}

func (vk *VerifyingKeyBis) randomize() {
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
