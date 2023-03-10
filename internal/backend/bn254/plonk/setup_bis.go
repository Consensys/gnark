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

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzgg "github.com/consensys/gnark-crypto/kzg"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// PlonkTrace stores a plonk trace as columns
type PlonkTrace struct {

	// Constants describing a plonk circuit. The first entries
	// of LQk (whose index correspond to the public inputs) are set to 0, and are to be
	// completed by the prover. At those indices i (so from 0 to nb_public_variables), LQl[i]=-1
	// so the first nb_public_variables constraints look like this:
	// -1*Wire[i] + 0* + 0 . It is zero when the constant coefficient is replaced by Wire[i].
	Ql, Qr, Qm, Qo, Qk *iop.Polynomial

	// Polynomials representing the splitted permutation. The full permutation's support is 3*N where N=nb wires.
	// The set of interpolation is <g> of size N, so to represent the permutation S we let S acts on the
	// set A=(<g>, u*<g>, u^{2}*<g>) of size 3*N, where u is outside <g> (its use is to shift the set <g>).
	// We obtain a permutation of A, A'. We split A' in 3 (A'_{1}, A'_{2}, A'_{3}), and S1, S2, S3 are
	// respectively the interpolation of A'_{1}, A'_{2}, A'_{3} on <g>.
	S1, S2, S3 *iop.Polynomial

	// S full permutation, i -> S[i]
	S []int64
}

// VerifyingKey stores the data needed to verify a proof:
// * The commitment scheme
// * Commitments of ql prepended with as many ones as there are public inputs
// * Commitments of qr, qm, qo, qk prepended with as many zeroes as there are public inputs
// * Commitments to S1, S2, S3
type VerifyingKeyBis struct {

	// Size circuit
	Size              uint64
	SizeInv           fr.Element
	Generator         fr.Element
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	KZGSRS *kzg.SRS

	// cosetShift generator of the coset on the small domain
	CosetShift fr.Element

	// S commitments to S1, S2, S3
	S [3]kzg.Digest

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Digest
}

// ProvingKey stores the data needed to generate a proof:
// * the commitment scheme
// * ql, prepended with as many ones as they are public inputs
// * qr, qm, qo prepended with as many zeroes as there are public inputs.
// * qk, prepended with as many zeroes as public inputs, to be completed by the prover
// with the list of public inputs.
// * sigma_1, sigma_2, sigma_3 in both basis
// * the copy constraint permutation
type ProvingKeyBis struct {

	// stores ql, qr, qm, qo, qk (-> to be completed by the prover)
	// and s1, s2, s3. They are set in canonical basis before generating the proof, they will be used
	// for computing the opening proofs (hence the canonical form). The canonical version
	// of qk incompleted is used in the linearisation polynomial.
	trace PlonkTrace

	// Verifying Key is embedded into the proving key (needed by Prove)
	Vk *VerifyingKeyBis

	// qr,ql,qm,qo in LagrangeCoset --> these are not serialized, but computed from Ql, Qr, Qm, Qo once.
	lcQl, lcQr, lcQm, lcQo *iop.Polynomial

	// LQk qk in Lagrange form -> to be completed by the prover. After being completed,
	LQk *iop.Polynomial

	// Domains used for the FFTs.
	// Domain[0] = small Domain
	// Domain[1] = big Domain
	Domain [2]fft.Domain

	// in lagrange coset basis --> these are not serialized, but computed from S1Canonical, S2Canonical, S3Canonical once.
	lcS1, lcS2, lcS3 *iop.Polynomial
}

func SetupBis(spr *cs.SparseR1CS, srs *kzg.SRS) (*ProvingKeyBis, *VerifyingKeyBis, error) {

	var pk ProvingKeyBis
	var vk VerifyingKeyBis
	pk.Vk = &vk
	// nbConstraints := len(spr.Constraints)

	// step 0: set the fft domains
	pk.Domain = buildDomains(spr)

	// step 1: set the verifying key
	pk.Vk.CosetShift.Set(&pk.Domain[0].FrMultiplicativeGen)
	vk.Size = pk.Domain[0].Cardinality
	vk.SizeInv.SetUint64(vk.Size).Inverse(&vk.SizeInv)
	vk.Generator.Set(&pk.Domain[0].Generator)
	vk.NbPublicVariables = uint64(len(spr.Public))
	if err := pk.InitKZGBis(srs); err != nil {
		return nil, nil, err
	}

	// step 2: ql, qr, qm, qo, qk in Lagrange Basis
	BuildTrace(spr, &pk.trace)

	// step 3: build the permutation and build the polynomials S1, S2, S3 to encode the permutation.
	// Note: at this stage, the permutation takes in account the placeholders
	nbVariables := spr.NbInternalVariables + len(spr.Public) + len(spr.Secret)
	buildPermutationBis(spr, &pk.trace, nbVariables)
	s := computePermutationPolynomialsBis(&pk.trace, &pk.Domain[0])
	pk.trace.S1 = s[0]
	pk.trace.S2 = s[1]
	pk.trace.S3 = s[2]

	// step 4: commit to s1, s2, s3, ql, qr, qm, qo, and (the incomplete version of) qk.
	// Also the canonical form of the polynomials will be used to compute the openings.
	pk.LQk = pk.trace.Qk.Clone() // it will be completed by the prover, and the evaluated on the coset
	err := commitTrace(&pk.trace, &pk)
	if err != nil {
		return nil, nil, err
	}

	// step 5: evaluate ql, qr, qm, qo, s1, s2, s3 on LagrangeCoset (NOT qk)
	// we clone them, because the canonical versions are going to be used in
	// the opening proof
	pk.lcQl = pk.trace.Ql.Clone().ToLagrangeCoset(&pk.Domain[1])
	pk.lcQr = pk.trace.Qr.Clone().ToLagrangeCoset(&pk.Domain[1])
	pk.lcQm = pk.trace.Qm.Clone().ToLagrangeCoset(&pk.Domain[1])
	pk.lcQo = pk.trace.Qo.Clone().ToLagrangeCoset(&pk.Domain[1])
	pk.lcS1 = pk.trace.S1.Clone().ToLagrangeCoset(&pk.Domain[1])
	pk.lcS2 = pk.trace.S2.Clone().ToLagrangeCoset(&pk.Domain[1])
	pk.lcS3 = pk.trace.S3.Clone().ToLagrangeCoset(&pk.Domain[1])

	return &pk, &vk, nil
}

// InitKZG inits pk.Vk.KZG using pk.Domain[0] cardinality and provided SRS
//
// This should be used after deserializing a ProvingKey
// as pk.Vk.KZG is NOT serialized
func (pk *ProvingKeyBis) InitKZGBis(srs kzgg.SRS) error {
	return pk.Vk.InitKZGBis(srs)
}

// InitKZG inits vk.KZG using provided SRS
//
// This should be used after deserializing a VerifyingKey
// as vk.KZG is NOT serialized
//
// Note that this instantiate a new FFT domain using vk.Size
func (vk *VerifyingKeyBis) InitKZGBis(srs kzgg.SRS) error {
	_srs := srs.(*kzg.SRS)

	if len(_srs.G1) < int(vk.Size) {
		return errors.New("kzg srs is too small")
	}
	vk.KZGSRS = _srs

	return nil
}

// BuildTrace fills the constatn columns ql, qr, qm, qo, qk from the sparser1cs.
// Size is the size of the system that is nb_constraints+nb_public_variables
func BuildTrace(spr *cs.SparseR1CS, pt *PlonkTrace) {

	nbConstraints := len(spr.Constraints)
	sizeSystem := uint64(nbConstraints + len(spr.Public))
	size := ecc.NextPowerOfTwo(uint64(sizeSystem))

	ql := make([]fr.Element, size)
	qr := make([]fr.Element, size)
	qm := make([]fr.Element, size)
	qo := make([]fr.Element, size)
	qk := make([]fr.Element, size)

	for i := 0; i < len(spr.Public); i++ { // placeholders (-PUB_INPUT_i + qk_i = 0) TODO should return error is size is inconsistant
		ql[i].SetOne().Neg(&ql[i])
		qr[i].SetZero()
		qm[i].SetZero()
		qo[i].SetZero()
		qk[i].SetZero() // → to be completed by the prover
	}
	offset := len(spr.Public)
	for i := 0; i < nbConstraints; i++ { // constraints

		ql[offset+i].Set(&spr.Coefficients[spr.Constraints[i].L.CoeffID()])
		qr[offset+i].Set(&spr.Coefficients[spr.Constraints[i].R.CoeffID()])
		qm[offset+i].Set(&spr.Coefficients[spr.Constraints[i].M[0].CoeffID()]).
			Mul(&qm[offset+i], &spr.Coefficients[spr.Constraints[i].M[1].CoeffID()])
		qo[offset+i].Set(&spr.Coefficients[spr.Constraints[i].O.CoeffID()])
		qk[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
	}

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}

	pt.Ql = iop.NewPolynomial(&ql, lagReg)
	pt.Qr = iop.NewPolynomial(&qr, lagReg)
	pt.Qm = iop.NewPolynomial(&qm, lagReg)
	pt.Qo = iop.NewPolynomial(&qo, lagReg)
	pt.Qk = iop.NewPolynomial(&qk, lagReg)

}

// commitTrace commits to every polynomials in the trace, and put
// the commitments int the verifying key.
func commitTrace(trace *PlonkTrace, pk *ProvingKeyBis) error {

	trace.Ql.ToCanonical(&pk.Domain[0]).ToRegular()
	trace.Qr.ToCanonical(&pk.Domain[0]).ToRegular()
	trace.Qm.ToCanonical(&pk.Domain[0]).ToRegular()
	trace.Qo.ToCanonical(&pk.Domain[0]).ToRegular()
	trace.Qk.ToCanonical(&pk.Domain[0]).ToRegular() // -> qk is not complete
	trace.S1.ToCanonical(&pk.Domain[0]).ToRegular()
	trace.S2.ToCanonical(&pk.Domain[0]).ToRegular()
	trace.S3.ToCanonical(&pk.Domain[0]).ToRegular()

	var err error
	if pk.Vk.Ql, err = kzg.Commit(pk.trace.Ql.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.Qr, err = kzg.Commit(pk.trace.Qr.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.Qm, err = kzg.Commit(pk.trace.Qm.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.Qo, err = kzg.Commit(pk.trace.Qo.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.Qk, err = kzg.Commit(pk.trace.Qk.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.S[0], err = kzg.Commit(pk.trace.S1.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.S[1], err = kzg.Commit(pk.trace.S2.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	if pk.Vk.S[2], err = kzg.Commit(pk.trace.S3.Coefficients(), pk.Vk.KZGSRS); err != nil {
		return err
	}
	return nil
}

// buildDomains creates the fft domains
func buildDomains(spr *cs.SparseR1CS) [2]fft.Domain {

	nbConstraints := len(spr.Constraints)
	var res [2]fft.Domain
	sizeSystem := uint64(nbConstraints + len(spr.Public)) // len(spr.Public) is for the placeholder constraints
	res[0] = *fft.NewDomain(sizeSystem)

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	if sizeSystem < 6 {
		res[1] = *fft.NewDomain(8 * sizeSystem)
	} else {
		res[1] = *fft.NewDomain(4 * sizeSystem)
	}
	return res
}

// buildPermutation builds the Permutation associated with a circuit.
//
// The permutation s is composed of cycles of maximum length such that
//
//	s. (l∥r∥o) = (l∥r∥o)
//
// , where l∥r∥o is the concatenation of the indices of l, r, o in
// ql.l+qr.r+qm.l.r+qo.O+k = 0.
//
// The permutation is encoded as a slice s of size 3*size(l), where the
// i-th entry of l∥r∥o is sent to the s[i]-th entry, so it acts on a tab
// like this: for i in tab: tab[i] = tab[permutation[i]]
func buildPermutationBis(spr *cs.SparseR1CS, pt *PlonkTrace, nbVariables int) {

	// nbVariables := spr.NbInternalVariables + len(spr.Public) + len(spr.Secret)
	sizeSolution := len(pt.Ql.Coefficients())
	sizePermutation := 3 * sizeSolution

	// init permutation
	permutation := make([]int64, sizePermutation)
	for i := 0; i < len(permutation); i++ {
		permutation[i] = -1
	}

	// init LRO position -> variable_ID
	lro := make([]int, sizePermutation) // position -> variable_ID
	for i := 0; i < len(spr.Public); i++ {
		lro[i] = i // IDs of LRO associated to placeholders (only L needs to be taken care of)
	}

	offset := len(spr.Public)
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
			permutation[i] = cycle[lro[i]]
		}
		cycle[lro[i]] = int64(i)
	}

	// complete the Permutation by filling the first IDs encountered
	for i := 0; i < sizePermutation; i++ {
		if permutation[i] == -1 {
			permutation[i] = cycle[lro[i]]
		}
	}

	pt.S = permutation
}

// computePermutationPolynomials computes the LDE (Lagrange basis) of the permutation.
// We let the permutation act on <g> || u<g> || u^{2}<g>, split the result in 3 parts,
// and interpolate each of the 3 parts on <g>.
func computePermutationPolynomialsBis(pt *PlonkTrace, domain *fft.Domain) [3]*iop.Polynomial {

	nbElmts := int(domain.Cardinality)

	var res [3]*iop.Polynomial

	// Lagrange form of ID
	evaluationIDSmallDomain := getSupportPermutation(domain)

	// Lagrange form of S1, S2, S3
	s1Canonical := make([]fr.Element, nbElmts)
	s2Canonical := make([]fr.Element, nbElmts)
	s3Canonical := make([]fr.Element, nbElmts)
	for i := 0; i < nbElmts; i++ {
		s1Canonical[i].Set(&evaluationIDSmallDomain[pt.S[i]])
		s2Canonical[i].Set(&evaluationIDSmallDomain[pt.S[nbElmts+i]])
		s3Canonical[i].Set(&evaluationIDSmallDomain[pt.S[2*nbElmts+i]])
	}

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	res[0] = iop.NewPolynomial(&s1Canonical, lagReg)
	res[1] = iop.NewPolynomial(&s2Canonical, lagReg)
	res[2] = iop.NewPolynomial(&s3Canonical, lagReg)

	return res
}

// getSupportPermutation returns the support on which the permutation acts, it is
// <g> || u<g> || u^{2}<g>
func getSupportPermutation(domain *fft.Domain) []fr.Element {

	res := make([]fr.Element, 3*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
	}

	return res
}
