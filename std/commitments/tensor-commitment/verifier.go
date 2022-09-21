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

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sis"
)

var (
	ErrProofFailedOob = errors.New("[SNARK] the entry is out of bound")
)

type Proof struct {

	// list of entries of ̂{u} to query (see https://eprint.iacr.org/2021/1043.pdf for notations)
	// The entries are derived using Fiat Shamir.
	EntryList []frontend.Variable

	// columns on against which the linear combination is checked
	// (the i-th entry is the EntryList[i]-th column)
	Columns [][]frontend.Variable

	// Linear combination of the rows of the polynomial P written as a square matrix
	LinearCombination []frontend.Variable

	// root of unity (bigInt to avoid fr dependency)
	Generator big.Int
}

// evalAtPower returns p(x**n) where p is interpreted as a polynomial
// p[0] + p[1]X + .. p[len(p)-1]xˡᵉⁿ⁽ᵖ⁾⁻¹
func evalAtPower(api frontend.API, p []frontend.Variable, x big.Int, n frontend.Variable, sizeDomain uint64) frontend.Variable {

	// compute x' = x**n
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
		s, err := h.Sum(api, proof.Columns[i])
		if err != nil {
			return err
		}

		// the following loop selects the proof.EntryList[i]-th entry
		// of digest. digestProofEntryListi -> corresponds to digest[proof.EntryList[i]][:]
		digestProofEntryListi := make([]frontend.Variable, h.Degree)
		for j := 0; j < h.Degree; j++ {
			digestProofEntryListi[j] = 0
		}
		for j := 0; j < h.Degree; j++ { // for all elmts in a given entry of digest
			for k := 0; k < len(digest); k++ {
				cur := api.IsZero(api.Sub(k, proof.EntryList[i]))
				cur = api.Sub(1, cur)                                             // k==proof.EntryList[i] ⩽> cur=1; k!=proof.EntryList[i] ⩽> cur=0
				cur = api.Mul(cur, digest[k][j])                                  // k==proof.EntryList[i] ⩽> cur=digest[k][j]; k!=proof.EntryList[i] ⩽> cur=0
				digestProofEntryListi[j] = api.Add(digestProofEntryListi[j], cur) // k==proof.EntryList[i] ⩽> selector[j]+=digest[k][j]; k!=proof.EntryList[i] ⩽> selector+=0
			}
		}
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
			linCombEncoded = api.Add(linCombEncoded, &tmp)
		}

		// entry i of the encoded linear combination
		var encodedLinComb frontend.Variable
		encodedLinComb = evalAtPower(
			api,
			proof.LinearCombination,
			proof.Generator,
			proof.EntryList[i],
			h.Domain.Cardinality)

		// both values must be equal
		api.AssertIsEqual(encodedLinComb, linCombEncoded)
	}

	return nil
}
