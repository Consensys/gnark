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
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gsis "github.com/consensys/gnark-crypto/ecc/bn254/fr/sis"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrWrongSize = errors.New("size does not fit")
)

// RSisSnark wrapper around gnark-crypto sis. It implements
// the snark version of sis, based on public data contained in Sis.
// /!\ currently it does not implement the Hash interface in std/hash /!\
type RSisSnark gsis.RSis

// NewRSisSnark returns a wrapper around RSis
func NewRSisSnark(s gsis.RSis) RSisSnark {

	// only the key, the bound, and the degree are necessary
	// for the circuit version
	res := RSisSnark{
		A:            s.A,
		LogTwoBound:  s.LogTwoBound,
		Degree:       s.Degree,
		NbBytesToSum: s.NbBytesToSum,
	}

	return res

}

// Hash returns the RSis hash of v.
// v is supposed to be the raw data to be hashed, i.e. it is not preprocessed.
// v will be interpreted in binary like this: mbin := [bin(m[len(m)-1]) || bin(m[len(m)-2]) || ... ]
// where bin is big endian decomposition (corresponding to what Marshal() from gnark-crypto gives).
// If len(v) is smaller than needed, we padd with zeroes [bin(m[len(m)-1]) || bin(m[len(m)-2]) || ... || 0 || ...]
// Then mbin is processed per chunk of LogTwoBound bits, where each chunk corresponds
// to the coefficient of a polynomial.
func (r RSisSnark) Sum(api frontend.API, v []frontend.Variable) ([]frontend.Variable, error) {

	// check the size of v
	nbBytes := api.Compiler().Field().BitLen()
	if nbBytes%8 != 0 {
		nbBytes = (nbBytes-nbBytes%8)/8 + 1
	} else {
		nbBytes = nbBytes / 8
	}
	// if nbBytes*len(v) != r.NbBytesToSum {
	// 	return nil, ErrWrongSize
	// }

	// decompose v according to the bound
	nbBitsToSum := r.NbBytesToSum * 8
	nbBitsPerFrElement := nbBytes * 8
	vBits := make([]frontend.Variable, nbBitsToSum)
	for i := 0; i < nbBitsToSum; i++ {
		vBits[i] = 0
	}

	// the padding (if needed) is done by appending zeroes in gnark-crypto.
	// Since here the endianness is reversed (little endian), the resulting
	// slice vBits must be prepended with zeroes. So since vBits is already
	// initialised with zeroes, we copy v in vBits from an offset equal to
	// len(vBits)-len(v)*nbBitsPerFrElements
	offset := nbBitsToSum - len(v)*nbBitsPerFrElement

	// because of the endianness, we store the bit decomposition of
	// by reversing v, and storing each components of v sequentially in that
	// order, in little endian: [ToBinary(v[len(v)-1]),..,ToBinary(v[0])]
	for i := 0; i < len(v); i++ {
		tmp := api.ToBinary(v[len(v)-i-1])
		copy(vBits[offset+i*nbBitsPerFrElement:], tmp)
	}

	nbCoefficientsM := r.Degree * len(r.A) // nbCoefficientsM

	m := make([]frontend.Variable, nbCoefficientsM)
	for i := 0; i < nbCoefficientsM; i++ {
		m[nbCoefficientsM-1-i] = api.FromBinary(vBits[i*r.LogTwoBound : (i+1)*r.LogTwoBound]...)
	}

	// compute the  multiplications mod X^{d}+1
	res := make([]frontend.Variable, r.Degree)
	for i := 0; i < r.Degree; i++ {
		res[i] = 0
	}
	for i := 0; i < len(r.A); i++ {
		tmp := mulMod(api, r.A[i], m[i*r.Degree:(i+1)*r.Degree])
		for j := 0; j < r.Degree; j++ {
			res[j] = api.Add(tmp[j], res[j])
		}
	}

	return res, nil
}

// mulMod computes p * q Mod X^d+1 where d = len(p) = len(q).
// It is assumed that p and q are of the same size.
func mulMod(api frontend.API, p []fr.Element, q []frontend.Variable) []frontend.Variable {

	d := len(p)
	res := make([]frontend.Variable, d)
	for i := 0; i < d; i++ {
		res[i] = 0
	}

	for i := 0; i < d; i++ {
		for j := 0; j < d-i; j++ {
			res[i+j] = api.Add(api.Mul(p[j], q[i]), res[i+j])
		}
		for j := d - i; j < d; j++ {
			res[j-d+i] = api.Sub(res[j-d+i], api.Mul(p[j], q[i]))
		}
	}

	return res

}
