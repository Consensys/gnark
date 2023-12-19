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

// Code generated by gnark DO NOT EDIT

package plonkfri

import (
	"math/big"
	"math/bits"
	"runtime"

	"github.com/consensys/gnark/backend/witness"

	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"

	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr/fft"

	cs "github.com/consensys/gnark/constraint/bls24-315"

	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr/fri"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/utils"
)

type Proof struct {
	// commitments to the solution vectors
	LROpp [3]fri.ProofOfProximity

	// commitment to Z (permutation polynomial)
	// Z   Commitment
	Zpp fri.ProofOfProximity

	// commitment to h1,h2,h3 such that h = h1 + X**n*h2 + X**2nh3 the quotient polynomial
	Hpp [3]fri.ProofOfProximity

	// opening proofs for L, R, O
	OpeningsLROmp [3]fri.OpeningProof

	// opening proofs for Z, Zu
	OpeningsZmp [2]fri.OpeningProof

	// opening proof for H
	OpeningsHmp [3]fri.OpeningProof

	// opening proofs for ql, qr, qm, qo, qk
	OpeningsQlQrQmQoQkincompletemp [5]fri.OpeningProof

	// openings of S1, S2, S3
	// OpeningsS1S2S3   [3]OpeningProof
	OpeningsS1S2S3mp [3]fri.OpeningProof

	// openings of Id1, Id2, Id3
	OpeningsId1Id2Id3mp [3]fri.OpeningProof
}

func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}

	var proof Proof

	// 0 - Fiat Shamir
	fs := fiatshamir.NewTranscript(opt.ChallengeHash, "gamma", "beta", "alpha", "zeta")

	// 1 - solve the system
	_solution, err := spr.Solve(fullWitness, opt.SolverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)

	// 2 - commit to lro
	blindedLCanonical, blindedRCanonical, blindedOCanonical, err := computeBlindedLROCanonical(
		evaluationLDomainSmall,
		evaluationRDomainSmall,
		evaluationODomainSmall,
		&pk.Domain[0])
	if err != nil {
		return nil, err
	}
	proof.LROpp[0], err = pk.Vk.Iopp.BuildProofOfProximity(blindedLCanonical)
	if err != nil {
		return nil, err
	}
	proof.LROpp[1], err = pk.Vk.Iopp.BuildProofOfProximity(blindedRCanonical)
	if err != nil {
		return nil, err
	}
	proof.LROpp[2], err = pk.Vk.Iopp.BuildProofOfProximity(blindedOCanonical)
	if err != nil {
		return nil, err
	}

	// 3 - compute Z, challenges are derived using L, R, O + public inputs
	fw, ok := fullWitness.Vector().(fr.Vector)
	if !ok {
		return nil, witness.ErrInvalidWitness
	}
	dataFiatShamir := make([][fr.Bytes]byte, len(spr.Public)+3)
	for i := 0; i < len(spr.Public); i++ {
		copy(dataFiatShamir[i][:], fw[i].Marshal())
	}
	copy(dataFiatShamir[len(spr.Public)][:], proof.LROpp[0].ID)
	copy(dataFiatShamir[len(spr.Public)+1][:], proof.LROpp[1].ID)
	copy(dataFiatShamir[len(spr.Public)+2][:], proof.LROpp[2].ID)

	beta, err := deriveRandomnessFixedSize(fs, "gamma", dataFiatShamir...)
	if err != nil {
		return nil, err
	}

	gamma, err := deriveRandomness(fs, "beta", nil)
	if err != nil {
		return nil, err
	}

	//var beta, gamma fr.Element
	//beta.SetUint64(9)
	// gamma.SetString("10")
	blindedZCanonical, err := computeBlindedZCanonical(
		evaluationLDomainSmall,
		evaluationRDomainSmall,
		evaluationODomainSmall,
		pk, beta, gamma)
	if err != nil {
		return nil, err
	}

	// 4 - commit Z
	proof.Zpp, err = pk.Vk.Iopp.BuildProofOfProximity(blindedZCanonical)
	if err != nil {
		return nil, err
	}

	// 5 - compute H
	// var alpha fr.Element
	alpha, err := deriveRandomness(fs, "alpha", proof.Zpp.ID)
	if err != nil {
		return nil, err
	}
	// alpha.SetUint64(11)

	evaluationQkCompleteDomainBigBitReversed := make([]fr.Element, pk.Domain[1].Cardinality)
	copy(evaluationQkCompleteDomainBigBitReversed, fw[:len(spr.Public)])
	copy(evaluationQkCompleteDomainBigBitReversed[len(spr.Public):], pk.LQkIncompleteDomainSmall[len(spr.Public):])
	pk.Domain[0].FFTInverse(evaluationQkCompleteDomainBigBitReversed[:pk.Domain[0].Cardinality], fft.DIF)
	fft.BitReverse(evaluationQkCompleteDomainBigBitReversed[:pk.Domain[0].Cardinality])

	evaluationQkCompleteDomainBigBitReversed = fftBigCosetWOBitReverse(evaluationQkCompleteDomainBigBitReversed, &pk.Domain[1])

	evaluationBlindedLDomainBigBitReversed := fftBigCosetWOBitReverse(blindedLCanonical, &pk.Domain[1])
	evaluationBlindedRDomainBigBitReversed := fftBigCosetWOBitReverse(blindedRCanonical, &pk.Domain[1])
	evaluationBlindedODomainBigBitReversed := fftBigCosetWOBitReverse(blindedOCanonical, &pk.Domain[1])

	evaluationConstraintsDomainBigBitReversed := evalConstraintsInd(
		pk,
		evaluationBlindedLDomainBigBitReversed,
		evaluationBlindedRDomainBigBitReversed,
		evaluationBlindedODomainBigBitReversed,
		evaluationQkCompleteDomainBigBitReversed)

	evaluationBlindedZDomainBigBitReversed := fftBigCosetWOBitReverse(blindedZCanonical, &pk.Domain[1])

	evaluationOrderingDomainBigBitReversed := evaluateOrderingDomainBigBitReversed(
		pk,
		evaluationBlindedZDomainBigBitReversed,
		evaluationBlindedLDomainBigBitReversed,
		evaluationBlindedRDomainBigBitReversed,
		evaluationBlindedODomainBigBitReversed,
		beta, gamma)

	h1Canonical, h2Canonical, h3Canonical := computeQuotientCanonical(
		pk,
		evaluationConstraintsDomainBigBitReversed,
		evaluationOrderingDomainBigBitReversed,
		evaluationBlindedZDomainBigBitReversed,
		alpha)

	// 6 - commit to H
	proof.Hpp[0], err = pk.Vk.Iopp.BuildProofOfProximity(h1Canonical)
	if err != nil {
		return nil, err
	}
	proof.Hpp[1], err = pk.Vk.Iopp.BuildProofOfProximity(h2Canonical)
	if err != nil {
		return nil, err
	}
	proof.Hpp[2], err = pk.Vk.Iopp.BuildProofOfProximity(h3Canonical)
	if err != nil {
		return nil, err
	}

	// 7 - build the opening proofs
	// compute the size of the domain of evaluation of the committed polynomial,
	// the opening position. The challenge zeta will be g^{i} where i is the opening
	// position, and g is the generator of the fri domain.
	rho := uint64(fri.GetRho())
	friSize := 2 * rho * pk.Vk.Size
	var bFriSize big.Int
	bFriSize.SetInt64(int64(friSize))
	frOpeningPosition, err := deriveRandomness(fs, "zeta", proof.Hpp[0].ID, proof.Hpp[1].ID, proof.Hpp[2].ID)
	if err != nil {
		return nil, err
	}
	var bOpeningPosition big.Int
	bOpeningPosition.SetBytes(frOpeningPosition.Marshal()).Mod(&bOpeningPosition, &bFriSize)
	openingPosition := bOpeningPosition.Uint64()

	// ql, qr, qm, qo, qkIncomplete
	proof.OpeningsQlQrQmQoQkincompletemp[0], err = pk.Vk.Iopp.Open(pk.CQl, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsQlQrQmQoQkincompletemp[1], err = pk.Vk.Iopp.Open(pk.CQr, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsQlQrQmQoQkincompletemp[2], err = pk.Vk.Iopp.Open(pk.CQm, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsQlQrQmQoQkincompletemp[3], err = pk.Vk.Iopp.Open(pk.CQo, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsQlQrQmQoQkincompletemp[4], err = pk.Vk.Iopp.Open(pk.CQkIncomplete, openingPosition)
	if err != nil {
		return &proof, err
	}

	// l, r, o
	proof.OpeningsLROmp[0], err = pk.Vk.Iopp.Open(blindedLCanonical, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsLROmp[1], err = pk.Vk.Iopp.Open(blindedRCanonical, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsLROmp[2], err = pk.Vk.Iopp.Open(blindedOCanonical, openingPosition)
	if err != nil {
		return &proof, err
	}

	// h0, h1, h2
	proof.OpeningsHmp[0], err = pk.Vk.Iopp.Open(h1Canonical, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsHmp[1], err = pk.Vk.Iopp.Open(h2Canonical, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsHmp[2], err = pk.Vk.Iopp.Open(h3Canonical, openingPosition)
	if err != nil {
		return &proof, err
	}

	// s0, s1, s2
	proof.OpeningsS1S2S3mp[0], err = pk.Vk.Iopp.Open(pk.Vk.SCanonical[0], openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsS1S2S3mp[1], err = pk.Vk.Iopp.Open(pk.Vk.SCanonical[1], openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsS1S2S3mp[2], err = pk.Vk.Iopp.Open(pk.Vk.SCanonical[2], openingPosition)
	if err != nil {
		return &proof, err
	}

	// id0, id1, id2
	proof.OpeningsId1Id2Id3mp[0], err = pk.Vk.Iopp.Open(pk.Vk.IdCanonical[0], openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsId1Id2Id3mp[1], err = pk.Vk.Iopp.Open(pk.Vk.IdCanonical[1], openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsId1Id2Id3mp[2], err = pk.Vk.Iopp.Open(pk.Vk.IdCanonical[2], openingPosition)
	if err != nil {
		return &proof, err
	}

	// zeta is shifted by g, the generator of Z/nZ where n is the number of constraints. We need
	// to query the "rho" factor from FRI to know by what should be shifted the opening position.
	// We multiply by 2 because FRI is instantiated with pk.Domain[0].Cardinality+2, which makes
	// the iop's domain of size rho*(2*pk.Domain[0].Cardinality).
	shiftedOpeningPosition := (openingPosition + uint64(2*rho)) % friSize
	proof.OpeningsZmp[0], err = pk.Vk.Iopp.Open(blindedZCanonical, openingPosition)
	if err != nil {
		return &proof, err
	}
	proof.OpeningsZmp[1], err = pk.Vk.Iopp.Open(blindedZCanonical, shiftedOpeningPosition)
	if err != nil {
		return &proof, err
	}

	return &proof, nil
}

// evaluateOrderingDomainBigBitReversed computes the evaluation of Z(uX)g1g2g3-Z(X)f1f2f3 on the odd
// cosets of the big domain.
//
// * z evaluation of the blinded permutation accumulator polynomial on odd cosets
// * l, r, o evaluation of the blinded solution vectors on odd cosets
// * gamma randomization
func evaluateOrderingDomainBigBitReversed(pk *ProvingKey, z, l, r, o []fr.Element, beta, gamma fr.Element) []fr.Element {

	nbElmts := int(pk.Domain[1].Cardinality)

	// computes  z_(uX)*(l(X)+s₁(X)*β+γ)*(r(X))+s₂(gⁱ)*β+γ)*(o(X))+s₃(X)*β+γ) - z(X)*(l(X)+X*β+γ)*(r(X)+u*X*β+γ)*(o(X)+u²*X*β+γ)
	// on the big domain (coset).
	res := make([]fr.Element, pk.Domain[1].Cardinality) // re use allocated memory for EvaluationS1BigDomain

	// utils variables useful for using bit reversed indices
	nn := uint64(64 - bits.TrailingZeros64(uint64(nbElmts)))

	// needed to shift LsZ
	toShift := int(pk.Domain[1].Cardinality / pk.Domain[0].Cardinality)

	var cosetShift, cosetShiftSquare fr.Element
	cosetShift.Set(&pk.Vk.CosetShift)
	cosetShiftSquare.Square(&pk.Vk.CosetShift)

	utils.Parallelize(int(pk.Domain[1].Cardinality), func(start, end int) {

		var evaluationIDBigDomain fr.Element
		evaluationIDBigDomain.Exp(pk.Domain[1].Generator, big.NewInt(int64(start))).
			Mul(&evaluationIDBigDomain, &pk.Domain[1].FrMultiplicativeGen)

		var f [3]fr.Element
		var g [3]fr.Element

		for i := start; i < end; i++ {

			_i := bits.Reverse64(uint64(i)) >> nn
			_is := bits.Reverse64(uint64((i+toShift)%nbElmts)) >> nn

			// in what follows gⁱ is understood as the generator of the chosen coset of domainBig
			f[0].Mul(&evaluationIDBigDomain, &beta).Add(&f[0], &l[_i]).Add(&f[0], &gamma)                               //l(gⁱ)+gⁱ*β+γ
			f[1].Mul(&evaluationIDBigDomain, &cosetShift).Mul(&f[1], &beta).Add(&f[1], &r[_i]).Add(&f[1], &gamma)       //r(gⁱ)+u*gⁱ*β+γ
			f[2].Mul(&evaluationIDBigDomain, &cosetShiftSquare).Mul(&f[2], &beta).Add(&f[2], &o[_i]).Add(&f[2], &gamma) //o(gⁱ)+u²*gⁱ*β+γ

			g[0].Mul(&pk.EvaluationS1BigDomain[_i], &beta).Add(&g[0], &l[_i]).Add(&g[0], &gamma) //l(gⁱ))+s1(gⁱ)*β+γ
			g[1].Mul(&pk.EvaluationS2BigDomain[_i], &beta).Add(&g[1], &r[_i]).Add(&g[1], &gamma) //r(gⁱ))+s2(gⁱ)*β+γ
			g[2].Mul(&pk.EvaluationS3BigDomain[_i], &beta).Add(&g[2], &o[_i]).Add(&g[2], &gamma) //o(gⁱ))+s3(gⁱ)*β+γ

			f[0].Mul(&f[0], &f[1]).Mul(&f[0], &f[2]).Mul(&f[0], &z[_i])  // z(gⁱ)*(l(gⁱ)+g^i*β+γ)*(r(g^i)+u*g^i*β+γ)*(o(g^i)+u²*g^i*β+γ)
			g[0].Mul(&g[0], &g[1]).Mul(&g[0], &g[2]).Mul(&g[0], &z[_is]) //  z_(ugⁱ)*(l(gⁱ))+s₁(gⁱ)*β+γ)*(r(gⁱ))+s₂(gⁱ)*β+γ)*(o(gⁱ))+s₃(gⁱ)*β+γ)

			res[_i].Sub(&g[0], &f[0]) // z_(ugⁱ)*(l(gⁱ))+s₁(gⁱ)*β+γ)*(r(gⁱ))+s₂(gⁱ)*β+γ)*(o(gⁱ))+s₃(gⁱ)*β+γ) - z(gⁱ)*(l(gⁱ)+g^i*β+γ)*(r(g^i)+u*g^i*β+γ)*(o(g^i)+u²*g^i*β+γ)

			evaluationIDBigDomain.Mul(&evaluationIDBigDomain, &pk.Domain[1].Generator) // gⁱ*g
		}
	})

	return res
}

// evalConstraintsInd computes the evaluation of lL+qrR+qqmL.R+qoO+k on
// the odd coset of (Z/8mZ)/(Z/4mZ), where m=nbConstraints+nbAssertions.
//
// * lsL, lsR, lsO are the evaluation of the blinded solution vectors on odd cosets
// * lsQk is the completed version of qk, in canonical version
//
// lsL, lsR, lsO are in bit reversed order, lsQk is in the correct order.
func evalConstraintsInd(pk *ProvingKey, lsL, lsR, lsO, lsQk []fr.Element) []fr.Element {

	res := make([]fr.Element, pk.Domain[1].Cardinality)
	// nn := uint64(64 - bits.TrailingZeros64(pk.Domain[1].Cardinality))

	utils.Parallelize(len(res), func(start, end int) {

		var t0, t1 fr.Element

		for i := start; i < end; i++ {

			// irev := bits.Reverse64(uint64(i)) >> nn

			t1.Mul(&pk.EvaluationQmDomainBigBitReversed[i], &lsR[i]) // qm.r
			t1.Add(&t1, &pk.EvaluationQlDomainBigBitReversed[i])     // qm.r + ql
			t1.Mul(&t1, &lsL[i])                                     //  qm.l.r + ql.l

			t0.Mul(&pk.EvaluationQrDomainBigBitReversed[i], &lsR[i])
			t0.Add(&t0, &t1) // qm.l.r + ql.l + qr.r

			t1.Mul(&pk.EvaluationQoDomainBigBitReversed[i], &lsO[i])
			t0.Add(&t0, &t1)          // ql.l + qr.r + qm.l.r + qo.o
			res[i].Add(&t0, &lsQk[i]) // ql.l + qr.r + qm.l.r + qo.o + k

		}
	})

	return res
}

// fftBigCosetWOBitReverse evaluates poly (canonical form) of degree m<n where n=domainBig.Cardinality
// on the odd coset of (Z/2nZ)/(Z/nZ).
//
// Puts the result in res of size n.
// Warning: result is in bit reversed order, we do a bit reverse operation only once in computeQuotientCanonical
func fftBigCosetWOBitReverse(poly []fr.Element, domainBig *fft.Domain) []fr.Element {

	res := make([]fr.Element, domainBig.Cardinality)

	// we copy poly in res and scale by coset here
	// to avoid FFT scaling on domainBig.Cardinality (res is very sparse)
	utils.Parallelize(len(poly), func(start, end int) {
		for i := start; i < end; i++ {
			res[i].Mul(&poly[i], &domainBig.CosetTable[i])
		}
	}, runtime.NumCPU()/2)
	domainBig.FFT(res, fft.DIF)
	return res
}

// evaluateXnMinusOneDomainBigCoset evalutes Xᵐ-1 on DomainBig coset
func evaluateXnMinusOneDomainBigCoset(domainBig, domainSmall *fft.Domain) []fr.Element {

	ratio := domainBig.Cardinality / domainSmall.Cardinality

	res := make([]fr.Element, ratio)

	expo := big.NewInt(int64(domainSmall.Cardinality))
	res[0].Exp(domainBig.FrMultiplicativeGen, expo)

	var t fr.Element
	t.Exp(domainBig.Generator, big.NewInt(int64(domainSmall.Cardinality)))

	for i := 1; i < int(ratio); i++ {
		res[i].Mul(&res[i-1], &t)
	}

	var one fr.Element
	one.SetOne()
	for i := 0; i < int(ratio); i++ {
		res[i].Sub(&res[i], &one)
	}

	return res
}

// computeQuotientCanonical computes h in canonical form, split as h1+X^mh2+X²mh3 such that
//
// qlL+qrR+qmL.R+qoO+k + alpha.(zu*g1*g2*g3-z*f1*f2*f3) + alpha**2*L1*(z-1)= h.Z
// \------------------/         \------------------------/             \-----/
//
//	constraintsInd			    constraintOrdering					startsAtOne
//
// constraintInd, constraintOrdering are evaluated on the odd cosets of (Z/8mZ)/(Z/mZ)
func computeQuotientCanonical(pk *ProvingKey, evaluationConstraintsIndBitReversed, evaluationConstraintOrderingBitReversed, evaluationBlindedZDomainBigBitReversed []fr.Element, alpha fr.Element) ([]fr.Element, []fr.Element, []fr.Element) {

	h := make([]fr.Element, pk.Domain[1].Cardinality)

	// evaluate Z = Xᵐ-1 on a coset of the big domain
	evaluationXnMinusOneInverse := evaluateXnMinusOneDomainBigCoset(&pk.Domain[1], &pk.Domain[0])
	evaluationXnMinusOneInverse = fr.BatchInvert(evaluationXnMinusOneInverse)

	// computes L₁ (canonical form)
	startsAtOne := make([]fr.Element, pk.Domain[1].Cardinality)
	for i := 0; i < int(pk.Domain[0].Cardinality); i++ {
		startsAtOne[i].Set(&pk.Domain[0].CardinalityInv)
	}
	pk.Domain[1].FFT(startsAtOne, fft.DIF, fft.OnCoset())

	// ql(X)L(X)+qr(X)R(X)+qm(X)L(X)R(X)+qo(X)O(X)+k(X) + α.(z(μX)*g₁(X)*g₂(X)*g₃(X)-z(X)*f₁(X)*f₂(X)*f₃(X)) + α**2*L₁(X)(Z(X)-1)
	// on a coset of the big domain
	nn := uint64(64 - bits.TrailingZeros64(pk.Domain[1].Cardinality))

	var one fr.Element
	one.SetOne()

	ratio := pk.Domain[1].Cardinality / pk.Domain[0].Cardinality

	utils.Parallelize(int(pk.Domain[1].Cardinality), func(start, end int) {
		var t fr.Element
		for i := uint64(start); i < uint64(end); i++ {

			_i := bits.Reverse64(i) >> nn

			t.Sub(&evaluationBlindedZDomainBigBitReversed[_i], &one) // evaluates L₁(X)*(Z(X)-1) on a coset of the big domain
			h[_i].Mul(&startsAtOne[_i], &t).Mul(&h[_i], &alpha).
				Add(&h[_i], &evaluationConstraintOrderingBitReversed[_i]).
				Mul(&h[_i], &alpha).
				Add(&h[_i], &evaluationConstraintsIndBitReversed[_i]).
				Mul(&h[_i], &evaluationXnMinusOneInverse[i%ratio])
		}
	})

	// put h in canonical form. h is of degree 3*(n+1)+2.
	// using fft.DIT put h revert bit reverse
	pk.Domain[1].FFTInverse(h, fft.DIT, fft.OnCoset())

	// degree of hi is n+2 because of the blinding
	h1 := h[:pk.Domain[0].Cardinality+2]
	h2 := h[pk.Domain[0].Cardinality+2 : 2*(pk.Domain[0].Cardinality+2)]
	h3 := h[2*(pk.Domain[0].Cardinality+2) : 3*(pk.Domain[0].Cardinality+2)]

	return h1, h2, h3

}

// computeZ computes Z, in canonical basis, where:
//
//   - Z of degree n (domainNum.Cardinality)
//
//   - Z(1)=1
//     (l_i+z**i+gamma)*(r_i+u*z**i+gamma)*(o_i+u**2z**i+gamma)
//
//   - for i>0: Z(u**i) = Pi_{k<i} -------------------------------------------------------
//     (l_i+s1+gamma)*(r_i+s2+gamma)*(o_i+s3+gamma)
//
//   - l, r, o are the solution in Lagrange basis
func computeBlindedZCanonical(l, r, o []fr.Element, pk *ProvingKey, beta, gamma fr.Element) ([]fr.Element, error) {

	// note that z has more capacity has its memory is reused for blinded z later on
	z := make([]fr.Element, pk.Domain[0].Cardinality, pk.Domain[0].Cardinality+3)
	nbElmts := int(pk.Domain[0].Cardinality)
	gInv := make([]fr.Element, pk.Domain[0].Cardinality)

	z[0].SetOne()
	gInv[0].SetOne()

	evaluationIDSmallDomain := getIDSmallDomain(&pk.Domain[0])

	utils.Parallelize(nbElmts-1, func(start, end int) {

		var f [3]fr.Element
		var g [3]fr.Element

		for i := start; i < end; i++ {

			f[0].Mul(&evaluationIDSmallDomain[i], &beta).Add(&f[0], &l[i]).Add(&f[0], &gamma)           //lᵢ+g^i*β+γ
			f[1].Mul(&evaluationIDSmallDomain[i+nbElmts], &beta).Add(&f[1], &r[i]).Add(&f[1], &gamma)   //rᵢ+u*g^i*β+γ
			f[2].Mul(&evaluationIDSmallDomain[i+2*nbElmts], &beta).Add(&f[2], &o[i]).Add(&f[2], &gamma) //oᵢ+u²*g^i*β+γ

			g[0].Mul(&evaluationIDSmallDomain[pk.Permutation[i]], &beta).Add(&g[0], &l[i]).Add(&g[0], &gamma)           //lᵢ+s₁(g^i)*β+γ
			g[1].Mul(&evaluationIDSmallDomain[pk.Permutation[i+nbElmts]], &beta).Add(&g[1], &r[i]).Add(&g[1], &gamma)   //rᵢ+s₂(g^i)*β+γ
			g[2].Mul(&evaluationIDSmallDomain[pk.Permutation[i+2*nbElmts]], &beta).Add(&g[2], &o[i]).Add(&g[2], &gamma) //oᵢ+s₃(g^i)*β+γ

			f[0].Mul(&f[0], &f[1]).Mul(&f[0], &f[2]) // (lᵢ+g^i*β+γ)*(rᵢ+u*g^i*β+γ)*(oᵢ+u²*g^i*β+γ)
			g[0].Mul(&g[0], &g[1]).Mul(&g[0], &g[2]) //  (lᵢ+s₁(g^i)*β+γ)*(rᵢ+s₂(g^i)*β+γ)*(oᵢ+s₃(g^i)*β+γ)

			gInv[i+1] = g[0]
			z[i+1] = f[0]

		}
	})

	gInv = fr.BatchInvert(gInv)
	for i := 1; i < nbElmts; i++ {
		z[i].Mul(&z[i], &z[i-1]).
			Mul(&z[i], &gInv[i])
	}

	pk.Domain[0].FFTInverse(z, fft.DIF)
	fft.BitReverse(z)

	return blindPoly(z, pk.Domain[0].Cardinality, 2)

}

// computeBlindedLROCanonical
// l, r, o in canonical basis with blinding
func computeBlindedLROCanonical(
	ll, lr, lo []fr.Element, domain *fft.Domain) (bcl, bcr, bco []fr.Element, err error) {

	// note that bcl, bcr and bco reuses cl, cr and co memory
	cl := make([]fr.Element, domain.Cardinality, domain.Cardinality+2)
	cr := make([]fr.Element, domain.Cardinality, domain.Cardinality+2)
	co := make([]fr.Element, domain.Cardinality, domain.Cardinality+2)

	chDone := make(chan error, 2)

	go func() {
		var err error
		copy(cl, ll)
		domain.FFTInverse(cl, fft.DIF)
		fft.BitReverse(cl)
		bcl, err = blindPoly(cl, domain.Cardinality, 1)
		chDone <- err
	}()
	go func() {
		var err error
		copy(cr, lr)
		domain.FFTInverse(cr, fft.DIF)
		fft.BitReverse(cr)
		bcr, err = blindPoly(cr, domain.Cardinality, 1)
		chDone <- err
	}()
	copy(co, lo)
	domain.FFTInverse(co, fft.DIF)
	fft.BitReverse(co)
	if bco, err = blindPoly(co, domain.Cardinality, 1); err != nil {
		return
	}
	err = <-chDone
	if err != nil {
		return
	}
	err = <-chDone
	return
}

// blindPoly blinds a polynomial by adding a Q(X)*(X**degree-1), where deg Q = order.
//
// * cp polynomial in canonical form
// * rou root of unity, meaning the blinding factor is multiple of X**rou-1
// * bo blinding order,  it's the degree of Q, where the blinding is Q(X)*(X**degree-1)
//
// WARNING:
// pre condition degree(cp) ⩽ rou + bo
// pre condition cap(cp) ⩾ int(totalDegree + 1)
func blindPoly(cp []fr.Element, rou, bo uint64) ([]fr.Element, error) {

	// degree of the blinded polynomial is max(rou+order, cp.Degree)
	totalDegree := rou + bo

	// re-use cp
	res := cp[:totalDegree+1]

	// random polynomial
	blindingPoly := make([]fr.Element, bo+1)

	for i := uint64(0); i < bo+1; i++ {
		if _, err := blindingPoly[i].SetRandom(); err != nil {
			return nil, err
		}
	}

	// blinding
	for i := uint64(0); i < bo+1; i++ {
		res[i].Sub(&res[i], &blindingPoly[i])
		res[rou+i].Add(&res[rou+i], &blindingPoly[i])
	}

	return res, nil
}

func deriveRandomnessFixedSize(fs *fiatshamir.Transcript, challenge string, data ...[fr.Bytes]byte) (fr.Element, error) {

	var r fr.Element
	for _, d := range data {
		if err := fs.Bind(challenge, d[:]); err != nil {
			return r, err
		}
	}

	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil

}

func deriveRandomness(fs *fiatshamir.Transcript, challenge string, data ...[]byte) (fr.Element, error) {

	var r fr.Element
	for _, d := range data {
		if err := fs.Bind(challenge, d); err != nil {
			return r, err
		}
	}

	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil

}
