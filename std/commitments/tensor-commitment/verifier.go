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

package tensorcommitment

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sis"
)

var (
	ErrProofFailedOob = errors.New("[SNARK] the entry is out of bound")
)

type Proof struct {

	// Size of the small domain of the tensor commitment
	// i.e. the domain to perform fft^-1
	SizeSmallDomainTensorCommitment uint64

	// Inverse of the generator of the small domain of the tensor commitment
	// i.e. the domain to perform fft^-1
	GenInvSmallDomainTensorCommitment fr.Element

	// Size of the big domain used in the tensor commitment
	// i.e. the domain that is used for the FFT, of size \rho*sizePoly
	SizeBigDomainTensorCommitment uint64

	// Generator of the big domain used in the tensor commitment
	// i.e. the domain that is used for the FFT, of size \rho*sizePoly
	GenBigDomainTensorCommitment big.Int

	// list of entries of ̂{u} to query (see https://eprint.iacr.org/2021/1043.pdf for notations)
	// The entries are derived using Fiat Shamir.
	EntryList []frontend.Variable

	// columns on against which the linear combination is checked
	// (the i-th entry is the EntryList[i]-th column)
	Columns [][]frontend.Variable

	// Linear combination of the rows of the polynomial P written as a square matrix
	LinearCombination []frontend.Variable
}

// evalAtPower returns p(x**n) where p is interpreted as a polynomial
// p[0] + p[1]X + .. p[len(p)-1]xˡᵉⁿ⁽ᵖ⁾⁻¹
func evalAtPower(api frontend.API, p []frontend.Variable, x big.Int, n frontend.Variable, sizeDomain uint64) frontend.Variable {

	// compute x' = x^{n}
	nBin := api.ToBinary(n, int(sizeDomain))
	var xexp frontend.Variable
	xexp = 1
	for i := 0; i < int(sizeDomain); i++ {
		xexp = api.Mul(xexp, xexp)
		u := api.Mul(xexp, x)
		xexp = api.Select(nBin[len(nBin)-1-i], u, xexp)
	}

	// compute p(x')
	var res frontend.Variable
	res = 0
	for i := 0; i < len(p); i++ {
		res = api.Mul(res, xexp)
		res = api.Add(p[len(p)-1-i], res)
	}

	return res

}

// returns tab[entry] assuming that tab is a regular array (n x m)
func selectEntry(api frontend.API, entry frontend.Variable, tab [][]frontend.Variable) []frontend.Variable {

	res := make([]frontend.Variable, len(tab[0]))

	for i := 0; i < len(tab[0]); i++ {
		res[i] = 0
	}

	for i := 0; i < len(tab[0]); i++ {
		for j := 0; j < len(tab); j++ {
			cur := api.IsZero(api.Sub(j, entry))
			cur = api.Mul(cur, tab[j][i])
			res[i] = api.Add(res[i], cur)
		}
	}
	return res
}

// computes fft^-1(p) where the fft is done on <generator>, a set of size cardinality.
// It is assumed that p is correctly sized.
//
// The fft is hardcoded with bn254 for now, to be more efficient than bigInt...
func fftInverse(api frontend.API, p []frontend.Variable, genInv fr.Element, cardinality uint64) []frontend.Variable {

	var cardInverse, g, x fr.Element
	cardInverse.SetUint64(cardinality).Inverse(&cardInverse)

	res := make([]frontend.Variable, cardinality)

	// starts of the incredibly inefficient implementation of the fft...
	g.SetOne()
	for i := 0; i < int(cardinality); i++ {
		x.Set(&cardInverse)
		res[i] = 0
		for j := 0; j < len(p); j++ {
			tmp := api.Mul(p[j], x.String())
			res[i] = api.Add(res[i], tmp)
			x.Mul(&x, &g)
		}
		g.Mul(&g, &genInv)
	}

	return res
}

// Verify a proof that digest is the hash of a  polynomial given a proof
// proof: proof that the commitment is correct
// digest: hash of the polynomial, where the hash is SIS
// l: random coefficients for the linear combination, chosen by the verifier
// TODO make this function private and add a Verify function that derives
// the randomness using Fiat Shamir
//
// The hash function by default here is SIS
func Verify(api frontend.API, proof Proof, digest [][]frontend.Variable, l []frontend.Variable, h sis.RSisSnark) error {

	// for each entry in the list -> it corresponds to the sampling
	// set on which we probabilistically check that
	// Encoded(linear_combination) = linear_combination(encoded)
	for i := 0; i < len(proof.EntryList); i++ {

		// check that the hash of the columns correspond to what's in the digest
		//s, err := h.Sum(api, proof.Columns[i])
		s, err := h.Sum(api, proof.Columns[i])
		if err != nil {
			return err
		}

		// we selects the proof.EntryList[i]-th entry
		digestProofEntryListi := selectEntry(api, proof.EntryList[i], digest)
		for j := 0; j < h.Degree; j++ {
			api.AssertIsEqual(digestProofEntryListi[j], s[j])
		}

		// linear combination of the i-th column, whose entries
		// are the entryList[i]-th entries of the encoded lines
		// of p
		var linCombEncoded, tmp frontend.Variable
		linCombEncoded = 0
		for j := 0; j < len(proof.Columns[i]); j++ {

			// linear combination of the encoded rows at column i
			tmp = api.Mul(proof.Columns[i][j], l[j])
			linCombEncoded = api.Add(linCombEncoded, tmp)
		}

		// entry i of the encoded linear combination
		// first we express proof.LinearCombination in canonical form
		// then we evaluate it at the required queries
		linCombCanonical := fftInverse(api, proof.LinearCombination, proof.GenInvSmallDomainTensorCommitment, proof.SizeSmallDomainTensorCommitment)

		var encodedLinComb frontend.Variable
		encodedLinComb = evalAtPower(
			api,
			linCombCanonical,
			proof.GenBigDomainTensorCommitment,
			proof.EntryList[i],
			proof.SizeBigDomainTensorCommitment)

		// both values must be equal
		api.AssertIsEqual(encodedLinComb, linCombEncoded)
	}

	return nil
}
