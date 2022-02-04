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
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/internal/backend/bn254/cs"

	kzgg "github.com/consensys/gnark-crypto/kzg"
)

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

	// qr,ql,qm,qo (in canonical basis).
	Ql, Qr, Qm, Qo []fr.Element

	// LQk (CQk) qk in Lagrange basis (canonical basis), prepended with as many zeroes as public inputs.
	// Storing LQk in Lagrange basis saves a fft...
	CQk, LQk []fr.Element

	// Domains used for the FFTs
	DomainSmall, DomainBig fft.Domain

	// s1, s2, s3 (L=Lagrange basis, C=canonical basis)
	LsID          []fr.Element
	LS1, LS2, LS3 []fr.Element
	CS1, CS2, CS3 []fr.Element

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

	// shifters for extending the permutation set: from s=<1,z,..,z**n-1>,
	// extended domain = s || shifter[0].s || shifter[1].s
	Shifter [2]fr.Element

	// Commitment scheme that is used for an instantiation of PLONK
	KZGSRS *kzg.SRS

	// S commitments to S1, S2, S3
	S [3]kzg.Digest

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Digest
}

// Setup sets proving and verifying keys
func Setup(spr *cs.SparseR1CS, srs *kzg.SRS) (*ProvingKey, *VerifyingKey, error) {
	var pk ProvingKey
	var vk VerifyingKey

	// The verifying key shares data with the proving key
	pk.Vk = &vk

	nbConstraints := len(spr.Constraints)

	// fft domains
	sizeSystem := uint64(nbConstraints + spr.NbPublicVariables) // spr.NbPublicVariables is for the placeholder constraints
	pk.DomainSmall = *fft.NewDomain(sizeSystem)

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	if sizeSystem < 6 {
		pk.DomainBig = *fft.NewDomain(8 * sizeSystem)
	} else {
		pk.DomainBig = *fft.NewDomain(4 * sizeSystem)
	}

	vk.Size = pk.DomainSmall.Cardinality
	vk.SizeInv.SetUint64(vk.Size).Inverse(&vk.SizeInv)
	vk.Generator.Set(&pk.DomainSmall.Generator)
	vk.NbPublicVariables = uint64(spr.NbPublicVariables)

	// shifters
	vk.Shifter[0].Set(&pk.DomainSmall.FrMultiplicativeGen)
	vk.Shifter[1].Square(&pk.DomainSmall.FrMultiplicativeGen)

	if err := pk.InitKZG(srs); err != nil {
		return nil, nil, err
	}

	// public polynomials corresponding to constraints: [ placholders | constraints | assertions ]
	pk.Ql = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.Qr = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.Qm = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.Qo = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.CQk = make([]fr.Element, pk.DomainSmall.Cardinality)
	pk.LQk = make([]fr.Element, pk.DomainSmall.Cardinality)

	for i := 0; i < spr.NbPublicVariables; i++ { // placeholders (-PUB_INPUT_i + qk_i = 0) TODO should return error is size is inconsistant
		pk.Ql[i].SetOne().Neg(&pk.Ql[i])
		pk.Qr[i].SetZero()
		pk.Qm[i].SetZero()
		pk.Qo[i].SetZero()
		pk.CQk[i].SetZero()
		pk.LQk[i].SetZero() // --> to be completed by the prover
	}
	offset := spr.NbPublicVariables
	for i := 0; i < nbConstraints; i++ { // constraints

		pk.Ql[offset+i].Set(&spr.Coefficients[spr.Constraints[i].L.CoeffID()])
		pk.Qr[offset+i].Set(&spr.Coefficients[spr.Constraints[i].R.CoeffID()])
		pk.Qm[offset+i].Set(&spr.Coefficients[spr.Constraints[i].M[0].CoeffID()]).
			Mul(&pk.Qm[offset+i], &spr.Coefficients[spr.Constraints[i].M[1].CoeffID()])
		pk.Qo[offset+i].Set(&spr.Coefficients[spr.Constraints[i].O.CoeffID()])
		pk.CQk[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
		pk.LQk[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
	}

	pk.DomainSmall.FFTInverse(pk.Ql, fft.DIF)
	pk.DomainSmall.FFTInverse(pk.Qr, fft.DIF)
	pk.DomainSmall.FFTInverse(pk.Qm, fft.DIF)
	pk.DomainSmall.FFTInverse(pk.Qo, fft.DIF)
	pk.DomainSmall.FFTInverse(pk.CQk, fft.DIF)
	fft.BitReverse(pk.Ql)
	fft.BitReverse(pk.Qr)
	fft.BitReverse(pk.Qm)
	fft.BitReverse(pk.Qo)
	fft.BitReverse(pk.CQk)

	// build permutation. Note: at this stage, the permutation takes in account the placeholders
	buildPermutation(spr, &pk)

	// set s1, s2, s3
	computeLDE(&pk)

	// Commit to the polynomials to set up the verifying key
	var err error
	if vk.Ql, err = kzg.Commit(pk.Ql, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qr, err = kzg.Commit(pk.Qr, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qm, err = kzg.Commit(pk.Qm, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qo, err = kzg.Commit(pk.Qo, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qk, err = kzg.Commit(pk.CQk, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[0], err = kzg.Commit(pk.CS1, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[1], err = kzg.Commit(pk.CS2, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[2], err = kzg.Commit(pk.CS3, vk.KZGSRS); err != nil {
		return nil, nil, err
	}

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

// computeLDE computes the LDE (Lagrange basis) of the permutations
// s1, s2, s3.
//
// ex: z gen of Z/mZ, u gen of Z/8mZ, then
//
// 1	z 	..	z**n-1	|	u	uz	..	u*z**n-1	|	u**2	u**2*z	..	u**2*z**n-1  |
//  																					 |
//        																				 | Permutation
// s11  s12 ..   s1n	   s21 s22 	 ..		s2n		     s31 	s32 	..		s3n		 v
// \---------------/       \--------------------/        \------------------------/
// 		s1 (LDE)                s2 (LDE)                          s3 (LDE)
func computeLDE(pk *ProvingKey) {

	nbElmt := int(pk.DomainSmall.Cardinality)

	// sID = [1,z,..,z**n-1,u,uz,..,uz**n-1,u**2,u**2.z,..,u**2.z**n-1]
	sID := make([]fr.Element, 3*nbElmt)
	sID[0].SetOne()
	sID[nbElmt].Set(&pk.DomainSmall.FrMultiplicativeGen)
	sID[2*nbElmt].Square(&pk.DomainSmall.FrMultiplicativeGen)

	for i := 1; i < nbElmt; i++ {
		sID[i].Mul(&sID[i-1], &pk.DomainSmall.Generator)                   // z**i -> z**i+1
		sID[i+nbElmt].Mul(&sID[nbElmt+i-1], &pk.DomainSmall.Generator)     // u*z**i -> u*z**i+1
		sID[i+2*nbElmt].Mul(&sID[2*nbElmt+i-1], &pk.DomainSmall.Generator) // u**2*z**i -> u**2*z**i+1
	}

	// Lagrange form of S1, S2, S3
	pk.LS1 = make([]fr.Element, nbElmt)
	pk.LS2 = make([]fr.Element, nbElmt)
	pk.LS3 = make([]fr.Element, nbElmt)
	for i := 0; i < nbElmt; i++ {
		pk.LS1[i].Set(&sID[pk.Permutation[i]])
		pk.LS2[i].Set(&sID[pk.Permutation[nbElmt+i]])
		pk.LS3[i].Set(&sID[pk.Permutation[2*nbElmt+i]])
	}

	// Canonical form of S1, S2, S3
	pk.CS1 = make([]fr.Element, nbElmt)
	pk.CS2 = make([]fr.Element, nbElmt)
	pk.CS3 = make([]fr.Element, nbElmt)
	copy(pk.CS1, pk.LS1)
	copy(pk.CS2, pk.LS2)
	copy(pk.CS3, pk.LS3)
	pk.DomainSmall.FFTInverse(pk.CS1, fft.DIF)
	pk.DomainSmall.FFTInverse(pk.CS2, fft.DIF)
	pk.DomainSmall.FFTInverse(pk.CS3, fft.DIF)
	fft.BitReverse(pk.CS1)
	fft.BitReverse(pk.CS2)
	fft.BitReverse(pk.CS3)

}

// InitKZG inits pk.Vk.KZG using pk.DomainSmall cardinality and provided SRS
//
// This should be used after deserializing a ProvingKey
// as pk.Vk.KZG is NOT serialized
func (pk *ProvingKey) InitKZG(srs kzgg.SRS) error {
	return pk.Vk.InitKZG(srs)
}

// InitKZG inits vk.KZG using provided SRS
//
// This should be used after deserializing a VerifyingKey
// as vk.KZG is NOT serialized
//
// Note that this instantiate a new FFT domain using vk.Size
func (vk *VerifyingKey) InitKZG(srs kzgg.SRS) error {
	_srs := srs.(*kzg.SRS)

	if len(_srs.G1) < int(vk.Size) {
		return errors.New("kzg srs is too small")
	}
	vk.KZGSRS = _srs

	return nil
}

// NbPublicWitness returns the expected public witness size (number of field elements)
func (vk *VerifyingKey) NbPublicWitness() int {
	return int(vk.NbPublicVariables)
}

// VerifyingKey returns pk.Vk
func (pk *ProvingKey) VerifyingKey() interface{} {
	return pk.Vk
}
