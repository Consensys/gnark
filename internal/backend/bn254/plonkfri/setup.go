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

package plonkfri

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
)

type Commitment []fr.Element

type OpeningProof struct {
	Val fr.Element
}

type CommitmentScheme interface {
	Commit(a []fr.Element) Commitment
	Open(c Commitment, p fr.Element) OpeningProof
	Verify(c Commitment, o OpeningProof, point fr.Element) bool
}

type MockCommitment struct{}

func (m MockCommitment) Commit(a []fr.Element) Commitment {
	res := make([]fr.Element, len(a))
	copy(res, a)
	return res
}

func (m MockCommitment) Open(c Commitment, p fr.Element) OpeningProof {
	var r fr.Element
	for i := len(c) - 1; i >= 0; i-- {
		r.Mul(&r, &p).Add(&r, &c[i])
	}
	return OpeningProof{
		Val: r,
	}
}

func (m MockCommitment) Verify(c Commitment, o OpeningProof, point fr.Element) bool {
	var r fr.Element
	for i := len(c) - 1; i >= 0; i-- {
		r.Mul(&r, &point).Add(&r, &c[i])
	}
	return r.Equal(&o.Val)
}

// ProvingKey stores the data needed to generate a proof:
// * the commitment scheme
// * ql, prepended with as many ones as they are public inputs
// * qr, qm, qo prepended with as many zeroes as there are public inputs.
// * qk, prepended with as many zeroes as public inputs, to be completed by the prover
// with the list of public inputs.
// * sigma_1, sigma_2, sigma_3 in both basis
// * the copy constraint permutation
type ProvingKey struct {

	// Verifying Key is embedded into the proving key (needed by Prove)
	Vk *VerifyingKey

	// qr,ql,qm,qo and Qk incomplete (Ls=Lagrange basis big domain, L=Lagrange basis small domain, C=canonical basis)
	LsQl, LsQr, LsQm, LsQo, LQkIncomplete []fr.Element
	CQl, CQr, CQm, CQo, CQkIncomplete     []fr.Element

	// commitment scheme
	Cscheme MockCommitment

	// Domains used for the FFTs
	DomainSmall, DomainBig fft.Domain

	// s1, s2, s3 (L=Lagrange basis small domain, C=canonical basis, Ls=Lagrange Shifted big domain)
	LId                 []fr.Element
	LsId1, LsId2, LsId3 []fr.Element
	LsS1, LsS2, LsS3    []fr.Element

	// position -> permuted position (position in [0,3*sizeSystem-1])
	Permutation []int64
}

// VerifyingKey stores the data needed to verify a proof:
// * The commitment scheme
// * Commitments of ql prepended with as many ones as there are public inputs
// * Commitments of qr, qm, qo, qk prepended with as many zeroes as there are public inputs
// * Commitments to S1, S2, S3
type VerifyingKey struct {

	// Size circuit
	Size              uint64
	SizeInv           fr.Element
	Generator         fr.Element
	NbPublicVariables uint64

	// commitment scheme
	Cscheme MockCommitment

	// S commitments to S1, S2, S3
	S [3]Commitment

	// Id commitments to Id1, Id2, Id3
	Id [3]Commitment

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, QkIncomplete Commitment
}

// Setup sets proving and verifying keys
func Setup(spr *cs.SparseR1CS) (*ProvingKey, *VerifyingKey, error) {

	var pk ProvingKey
	var vk VerifyingKey

	// The verifying key shares data with the proving key
	pk.Vk = &vk

	nbConstraints := len(spr.Constraints)

	// fft domains
	sizeSystem := uint64(nbConstraints + spr.NbPublicVariables) // spr.NbPublicVariables is for the placeholder constraints
	pk.DomainSmall = *fft.NewDomain(sizeSystem, 0, false)

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	if sizeSystem < 6 {
		pk.DomainBig = *fft.NewDomain(8*sizeSystem, 1, false)
	} else {
		pk.DomainBig = *fft.NewDomain(4*sizeSystem, 1, false)
	}

	vk.Size = pk.DomainSmall.Cardinality
	vk.SizeInv.SetUint64(vk.Size).Inverse(&vk.SizeInv)
	vk.Generator.Set(&pk.DomainSmall.Generator)
	vk.NbPublicVariables = uint64(spr.NbPublicVariables)

	// public polynomials corresponding to constraints: [ placholders | constraints | assertions ]
	pk.LsQl = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsQr = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsQm = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsQo = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LQkIncomplete = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.CQkIncomplete = make([]fr.Element, pk.DomainSmall.Cardinality)

	for i := 0; i < spr.NbPublicVariables; i++ { // placeholders (-PUB_INPUT_i + qk_i = 0) TODO should return error is size is inconsistant
		pk.LsQl[i].SetOne().Neg(&pk.LsQl[i])
		pk.LsQr[i].SetZero()
		pk.LsQm[i].SetZero()
		pk.LsQo[i].SetZero()
		pk.LQkIncomplete[i].SetZero()                 // --> to be completed by the prover
		pk.CQkIncomplete[i].Set(&pk.LQkIncomplete[i]) // --> to be completed by the prover
	}
	offset := spr.NbPublicVariables
	for i := 0; i < nbConstraints; i++ { // constraints

		pk.LsQl[offset+i].Set(&spr.Coefficients[spr.Constraints[i].L.CoeffID()])
		pk.LsQr[offset+i].Set(&spr.Coefficients[spr.Constraints[i].R.CoeffID()])
		pk.LsQm[offset+i].Set(&spr.Coefficients[spr.Constraints[i].M[0].CoeffID()]).
			Mul(&pk.LsQm[offset+i], &spr.Coefficients[spr.Constraints[i].M[1].CoeffID()])
		pk.LsQo[offset+i].Set(&spr.Coefficients[spr.Constraints[i].O.CoeffID()])
		pk.LQkIncomplete[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
		pk.CQkIncomplete[offset+i].Set(&pk.LQkIncomplete[offset+i])
	}

	pk.DomainSmall.FFTInverse(pk.LsQl[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsQr[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsQm[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsQo[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.CQkIncomplete, fft.DIF, 0)
	fft.BitReverse(pk.LsQl[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsQr[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsQm[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsQo[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.CQkIncomplete)

	// Commit to the polynomials to set up the verifying key
	pk.CQl = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.CQr = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.CQm = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.CQo = make([]fr.Element, pk.DomainSmall.Cardinality)
	copy(pk.CQl, pk.LsQl)
	copy(pk.CQr, pk.LsQr)
	copy(pk.CQm, pk.LsQm)
	copy(pk.CQo, pk.LsQo)
	vk.Ql = vk.Cscheme.Commit(pk.CQl)
	vk.Qr = vk.Cscheme.Commit(pk.CQr)
	vk.Qm = vk.Cscheme.Commit(pk.CQm)
	vk.Qo = vk.Cscheme.Commit(pk.CQo)
	vk.QkIncomplete = vk.Cscheme.Commit(pk.CQkIncomplete)

	pk.DomainBig.FFT(pk.LsQl, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsQr, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsQm, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsQo, fft.DIF, 1)

	// build permutation. Note: at this stage, the permutation takes in account the placeholders
	buildPermutation(spr, &pk)

	// set s1, s2, s3
	computePermutationPolynomials(&pk, &vk)

	return &pk, &vk, nil

}

// buildPermutation builds the Permutation associated with a circuit.
//
// The permutation s is composed of cycles of maximum length such that
//
// 			s. (l||r||o) = (l||r||o)
//
//, where l||r||o is the concatenation of the indices of l, r, o in
// ql.l+qr.r+qm.l.r+qo.O+k = 0.
//
// The permutation is encoded as a slice s of size 3*size(l), where the
// i-th entry of l||r||o is sent to the s[i]-th entry, so it acts on a tab
// like this: for i in tab: tab[i] = tab[permutation[i]]
func buildPermutation(spr *cs.SparseR1CS, pk *ProvingKey) {

	nbVariables := spr.NbInternalVariables + spr.NbPublicVariables + spr.NbSecretVariables
	sizeSolution := int(pk.DomainSmall.Cardinality)

	// init permutation
	pk.Permutation = make([]int64, 3*sizeSolution)
	for i := 0; i < len(pk.Permutation); i++ {
		pk.Permutation[i] = -1
	}

	// init LRO position -> variable_ID
	lro := make([]int, 3*sizeSolution) // position -> variable_ID
	for i := 0; i < spr.NbPublicVariables; i++ {
		lro[i] = i // IDs of LRO associated to placeholders (only L needs to be taken care of)
	}

	offset := spr.NbPublicVariables
	for i := 0; i < len(spr.Constraints); i++ { // IDs of LRO associated to constraints
		lro[offset+i] = spr.Constraints[i].L.WireID()
		lro[sizeSolution+offset+i] = spr.Constraints[i].R.WireID()
		lro[2*sizeSolution+offset+i] = spr.Constraints[i].O.WireID()
	}

	// init cycle:
	// map ID -> last position the ID was seen
	cycle := make([]int64, nbVariables)
	for i := 0; i < len(cycle); i++ {
		cycle[i] = -1
	}

	for i := 0; i < len(lro); i++ {
		if cycle[lro[i]] != -1 {
			// if != -1, it means we already encountered this value
			// so we need to set the corresponding permutation index.
			pk.Permutation[i] = cycle[lro[i]]
		}
		cycle[lro[i]] = int64(i)
	}

	// complete the Permutation by filling the first IDs encountered
	for i := 0; i < len(pk.Permutation); i++ {
		if pk.Permutation[i] == -1 {
			pk.Permutation[i] = cycle[lro[i]]
		}
	}
}

// computePermutationPolynomials computes the LDE (Lagrange basis) of the permutations
// s1, s2, s3.
//
// 0	1 	..	n-1		|	n	n+1	..	2*n-1		|	2n		2n+1	..		3n-1     |
//  																					 |
//        																				 | Permutation
// s00  s01 ..   s0n-1	   s10 s11 	 ..		s1n-1 		s20 	s21 	..		s2n-1	 v
// \---------------/       \--------------------/        \------------------------/
// 		s1 (LDE)                s2 (LDE)                          s3 (LDE)
func computePermutationPolynomials(pk *ProvingKey, vk *VerifyingKey) {

	nbElmt := int(pk.DomainSmall.Cardinality)

	// sID = [0,..,n-1,n,..2n-1,2n,..,3n-1]
	pk.LId = make([]fr.Element, 3*nbElmt)
	pk.LId[0].SetZero()
	pk.LId[nbElmt].SetUint64(pk.DomainSmall.Cardinality)
	pk.LId[2*nbElmt].Double(&pk.LId[nbElmt])

	var one fr.Element
	one.SetOne()
	for i := 1; i < nbElmt; i++ {
		pk.LId[i].Add(&pk.LId[i-1], &one)
		pk.LId[i+nbElmt].Add(&pk.LId[nbElmt+i-1], &one)
		pk.LId[i+2*nbElmt].Add(&pk.LId[2*nbElmt+i-1], &one)
	}

	// canonical form of S1, S2, S3
	pk.LsS1 = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsS2 = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsS3 = make([]fr.Element, pk.DomainBig.Cardinality)
	for i := 0; i < nbElmt; i++ {
		pk.LsS1[i].Set(&pk.LId[pk.Permutation[i]])
		pk.LsS2[i].Set(&pk.LId[pk.Permutation[nbElmt+i]])
		pk.LsS3[i].Set(&pk.LId[pk.Permutation[2*nbElmt+i]])
	}

	// Evaluations of Sid1, Sid2, Sid3 on cosets of DomainBig
	pk.LsId1 = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsId2 = make([]fr.Element, pk.DomainBig.Cardinality)
	pk.LsId3 = make([]fr.Element, pk.DomainBig.Cardinality)
	copy(pk.LsId1, pk.LId[:nbElmt])
	copy(pk.LsId2, pk.LId[nbElmt:2*nbElmt])
	copy(pk.LsId3, pk.LId[2*nbElmt:])
	pk.DomainSmall.FFTInverse(pk.LsId1[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsId2[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsId3[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	fft.BitReverse(pk.LsId1[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsId2[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsId3[:pk.DomainSmall.Cardinality])
	vk.Id[0] = vk.Cscheme.Commit(pk.LsId1)
	vk.Id[1] = vk.Cscheme.Commit(pk.LsId2)
	vk.Id[2] = vk.Cscheme.Commit(pk.LsId3)
	pk.DomainBig.FFT(pk.LsId1, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsId2, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsId3, fft.DIF, 1)

	pk.DomainSmall.FFTInverse(pk.LsS1[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsS2[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	pk.DomainSmall.FFTInverse(pk.LsS3[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	fft.BitReverse(pk.LsS1[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsS2[:pk.DomainSmall.Cardinality])
	fft.BitReverse(pk.LsS3[:pk.DomainSmall.Cardinality])

	// commit S1, S2, S3
	vk.S[0] = vk.Cscheme.Commit(pk.LsS1[:pk.DomainSmall.Cardinality])
	vk.S[1] = vk.Cscheme.Commit(pk.LsS2[:pk.DomainSmall.Cardinality])
	vk.S[2] = vk.Cscheme.Commit(pk.LsS3[:pk.DomainSmall.Cardinality])

	// compute Lagrange shifted forms of S1, S2, S3 (bit reversed)
	pk.DomainBig.FFT(pk.LsS1, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsS2, fft.DIF, 1)
	pk.DomainBig.FFT(pk.LsS3, fft.DIF, 1)

}

// NbPublicWitness returns the expected public witness size (number of field elements)
func (vk *VerifyingKey) NbPublicWitness() int {
	return int(vk.NbPublicVariables)
}

// VerifyingKey returns pk.Vk
func (pk *ProvingKey) VerifyingKey() interface{} {
	return pk.Vk
}
