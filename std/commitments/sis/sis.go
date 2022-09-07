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

// RSisWrapper wrapper around gnark-crypto sis. It implements
// the snark version of sis, based on public data contained in Sis.
// /!\ currently it does not implement the Hash interface in std/hash /!\
type RSisWrapper gsis.RSis

// NewRSisWrapper returns a wrapper around RSis
func NewRSisWrapper(s gsis.RSis) RSisWrapper {

	// only the key, the bound, and the degree are necessary
	// for the circuit version
	res := RSisWrapper{
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
func (r RSisWrapper) Sum(api frontend.API, v []frontend.Variable) ([]frontend.Variable, error) {

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
	vBits := make([]frontend.Variable, r.NbBytesToSum*8)
	nbBitsPerVariables := nbBytes * 8
	for i := 0; i < len(v); i++ {
		tmp := api.ToBinary(v[i])
		for j := 0; j < nbBytes*8; j++ {
			// conversion to big endian...
			vBits[i*nbBitsPerVariables+j] = tmp[nbBitsPerVariables-1-j]
		}
	}

	// compute the  multiplications mod X^{d}+1
	return nil, nil
}

// mulMod computes p * q Mod X^d+1 where d = len(p) = len(q).
// It is assumed that p and q are of the same size.
func mulMod(api frontend.API, p, q []fr.Element) []frontend.Variable {

	d := len(p)
	res := make([]frontend.Variable, d)
	for i := 0; i < d; i++ {
		res[i] = 0
	}

	for i := 0; i < d; i++ {
		for j := 0; j < d-i; j++ {
			api.Add(api.Mul(p[j], q[j]), res[i+j])
		}
		for j := d - i; j < d; j++ {
			api.Sub(res[j-d+i], api.Mul(p[j], q[j]))
		}
	}

	return res

}
