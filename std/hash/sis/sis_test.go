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

package sis

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/sis"
	gsis "github.com/consensys/gnark-crypto/ecc/bn254/fr/sis"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type MulModTest struct {
	P    [8]fr.Element
	Q, R [8]frontend.Variable
}

func (circuit *MulModTest) Define(api frontend.API) error {

	r := mulMod(api, circuit.P[:], circuit.Q[:])

	for i := 0; i < len(r); i++ {
		api.AssertIsEqual(r[i], circuit.R[i])
	}

	return nil

}

func TestMulMod(t *testing.T) {

	// get correct data
	_rsis, err := gsis.NewRSis(5, 3, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	rsis := _rsis.(*gsis.RSis)

	p := make([]fr.Element, 8)
	q := make([]fr.Element, 8)
	_p := make([]fr.Element, 8)
	_q := make([]fr.Element, 8)

	for i := 0; i < 8; i++ {
		p[i].SetRandom()
		q[i].SetRandom()
	}
	copy(_p, p)
	copy(_q, q)

	rsis.Domain.FFT(_p, fft.DIF, true)
	rsis.Domain.FFT(_q, fft.DIF, true)

	r := rsis.MulMod(_p, _q)

	var witness MulModTest
	for i := 0; i < len(p); i++ {
		witness.P[i] = p[i]
		witness.Q[i] = q[i]
		witness.R[i] = r[i]
	}

	var circuit MulModTest
	for i := 0; i < len(circuit.P); i++ {
		circuit.P[i] = p[i]
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}

	twitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = ccs.IsSolved(twitness)
	if err != nil {
		t.Fatal(err)
	}

}

// SumTest
type SumTest struct {

	// Sis instance from gnark-crypto
	Sis sis.RSis

	// message to hash
	M []frontend.Variable

	// Expected result
	R []frontend.Variable
}

func (circuit *SumTest) Define(api frontend.API) error {

	// sis in a snark
	sisSnark := NewRSisSnark(circuit.Sis)

	// hash M
	h, err := sisSnark.Sum(api, circuit.M)
	if err != nil {
		return err
	}

	// check against the result
	for i := 0; i < len(h); i++ {
		api.AssertIsEqual(h[i], circuit.R[i])
	}

	return nil
}

func TestSum(t *testing.T) {

	// generate the witness
	// Sis with:
	// * key of size 8
	// * on \mathbb{Z}_r[X]/X^{8}+1
	// * with coefficients of M < 2^4 = 16
	// Note: this allows to hash 256bits to 256 bytes, so it's completely pointless
	// whith those parameters, it's for testing only
	rsis, err := gsis.NewRSis(5, 3, 4, 8)
	if err != nil {
		t.Fatal(err)
	}

	var toSum fr.Element
	toSum.SetString("5237501451071880303487629517413837912210424399515269294611144167440988308494")
	toSumBytes := toSum.Marshal()
	rsis.Write(toSumBytes)
	sum := rsis.Sum(nil)

	var res [8]fr.Element
	for i := 0; i < 8; i++ {
		res[i].SetBytes(sum[i*32 : (i+1)*32])
	}

	// witness
	var witness SumTest
	witness.M = make([]frontend.Variable, 1)
	witness.M[0] = toSum
	witness.R = make([]frontend.Variable, 8)
	for i := 0; i < 8; i++ {
		witness.R[i] = res[i]
	}
	witness.Sis = *(rsis.(*gsis.RSis))

	// circuit
	var circuit SumTest
	circuit.M = make([]frontend.Variable, 1)
	circuit.R = make([]frontend.Variable, 8)
	circuit.Sis = *(rsis.(*gsis.RSis))

	// compile...
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// solve the circuit
	twitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = ccs.IsSolved(twitness)
	if err != nil {
		t.Fatal(err)
	}

}
