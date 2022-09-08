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
// v is supposed to be the raw data to be hashed, i.e. it is not preprocessed
// so the len(v) corresponds to the number of entries of m, the vector multiplied
// by the key that produces the hash. m is insted built inside of Sum.
func (r RSisSnark) Sum(api frontend.API, v []frontend.Variable) ([]frontend.Variable, error) {

	// check the size of v
	nbBytes := api.Compiler().Field().BitLen()
	if nbBytes%8 != 0 {
		nbBytes = (nbBytes-nbBytes%8)/8 + 1
	} else {
		nbBytes = nbBytes / 8
	}
	if nbBytes*len(v) != r.NbBytesToSum {
		return nil, ErrWrongSize
	}

	// decompose v according to the bound
	nbBitsTotal := r.NbBytesToSum * 8
	vBits := make([]frontend.Variable, nbBitsTotal)
	nbBitsPerFrElement := nbBytes * 8
	// because of the endianness, we store the bit decomposition of
	// by reversing v, and storing each components of v sequentially in that
	// order, in little endian: [ToBinary(v[len(v)-1]),..,ToBinary(v[0])]
	for i := 0; i < len(v); i++ {
		tmp := api.ToBinary(v[len(v)-i-1])
		copy(vBits[i*nbBitsPerFrElement:], tmp)
	}
	sizeM := r.Degree * len(r.A) // sizeM
	m := make([]frontend.Variable, sizeM)
	for i := 0; i < sizeM; i++ {
		m[sizeM-1-i] = api.FromBinary(i * r.LogTwoBound)
	}

	// compute the  multiplications mod X^{d}+1
	res := make([]frontend.Variable, r.Degree)
	for i := 0; i < r.Degree; i++ {
		res[i] = 0
	}
	for i := 0; i < len(r.A); i++ {
		tmp := mulMod(api, r.A[i], m[i*r.LogTwoBound:(i+1)*r.LogTwoBound])
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
