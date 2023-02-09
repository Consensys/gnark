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

package plonk

import (
	"crypto/sha256"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"

	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/fft"

	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/iop"
	"github.com/consensys/gnark/constraint/bw6-761"

	"github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
)

type Proof struct {

	// Commitments to the solution vectors
	LRO [3]kzg.Digest

	// Commitment to Z, the permutation polynomial
	Z kzg.Digest

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Digest

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2
	BatchedProof kzg.BatchOpeningProof

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof
}

// Prove from the public data
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness fr.Vector, opt backend.ProverConfig) (*Proof, error) {

	log := logger.Logger().With().Str("curve", spr.CurveID().String()).Int("nbConstraints", len(spr.Constraints)).Str("backend", "plonk").Logger()
	start := time.Now()
	// pick a hash function that will be used to derive the challenges
	hFunc := sha256.New()

	// create a transcript manager to apply Fiat Shamir
	fs := fiatshamir.NewTranscript(hFunc, "gamma", "beta", "alpha", "zeta")

	// result
	proof := &Proof{}

	// compute the constraint system solution
	var solution []fr.Element
	var err error
	if solution, err = spr.Solve(fullWitness, opt); err != nil {
		if !opt.Force {
			return nil, err
		} else {
			// we need to fill solution with random values
			var r fr.Element
			_, _ = r.SetRandom()
			for i := len(spr.Public) + len(spr.Secret); i < len(solution); i++ {
				solution[i] = r
				r.Double(&r)
			}
		}
	}

	// query l, r, o in Lagrange basis, not blinded
	evaluationLDomainSmall, evaluationRDomainSmall, evaluationODomainSmall := evaluateLROSmallDomain(spr, pk, solution)

	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	liop := iop.NewPolynomial(evaluationLDomainSmall, lagReg)
	riop := iop.NewPolynomial(evaluationRDomainSmall, lagReg)
	oiop := iop.NewPolynomial(evaluationODomainSmall, lagReg)
	wliop := iop.NewWrappedPolynomial(liop)
	wriop := iop.NewWrappedPolynomial(riop)
	woiop := iop.NewWrappedPolynomial(oiop)
	wliop.ToCanonical(&pk.Domain[0]).ToRegular()
	wriop.ToCanonical(&pk.Domain[0]).ToRegular()
	woiop.ToCanonical(&pk.Domain[0]).ToRegular()

	// Blind l, r, o before committing
	bwliop := wliop.Clone().Blind(1)
	bwriop := wriop.Clone().Blind(1)
	bwoiop := woiop.Clone().Blind(1)
	if err := commitToLRO(bwliop.Coefficients, bwriop.Coefficients, bwoiop.Coefficients, proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	// The first challenge is derived using the public data: the commitments to the permutation,
	// the coefficients of the circuit, and the public inputs.
	// derive gamma from the Comm(blinded cl), Comm(blinded cr), Comm(blinded co)
	if err := bindPublicData(&fs, "gamma", *pk.Vk, fullWitness[:len(spr.Public)]); err != nil {
		return nil, err
	}
	gamma, err := deriveRandomness(&fs, "gamma", &proof.LRO[0], &proof.LRO[1], &proof.LRO[2])
	if err != nil {
		return nil, err
	}

	// Fiat Shamir this
	bbeta, err := fs.ComputeChallenge("beta")
	if err != nil {
		return nil, err
	}
	var beta fr.Element
	beta.SetBytes(bbeta)

	// compute the copy constraint's ratio
	// We copy liop, riop, oiop because they are fft'ed in the process.
	// We could have not copied them at the cost of doing one more bit reverse
	// per poly...
	ziop, err := iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{liop.Clone(), riop.Clone(), oiop.Clone()},
		pk.Permutation,
		beta,
		gamma,
		iop.Form{Basis: iop.Canonical, Layout: iop.Regular},
		&pk.Domain[0],
	)
	if err != nil {
		return proof, err
	}

	// commit to the blinded version of z
	bwziop := iop.NewWrappedPolynomial(&ziop)
	bwziop.Blind(2)
	proof.Z, err = kzg.Commit(bwziop.Coefficients, pk.Vk.KZGSRS, runtime.NumCPU()*2)
	if err != nil {
		return proof, err
	}

	// derive alpha from the Comm(l), Comm(r), Comm(o), Com(Z)
	alpha, err := deriveRandomness(&fs, "alpha", &proof.Z)
	if err != nil {
		return proof, err
	}

	// compute qk in canonical basis, completed with the public inputs
	qkCompletedCanonical := make([]fr.Element, pk.Domain[0].Cardinality)
	copy(qkCompletedCanonical, fullWitness[:len(spr.Public)])
	copy(qkCompletedCanonical[len(spr.Public):], pk.LQk[len(spr.Public):])
	pk.Domain[0].FFTInverse(qkCompletedCanonical, fft.DIF)
	fft.BitReverse(qkCompletedCanonical)

	// l, r, o are blinded here
	bwliop.ToLagrangeCoset(&pk.Domain[1])
	bwriop.ToLagrangeCoset(&pk.Domain[1])
	bwoiop.ToLagrangeCoset(&pk.Domain[1])
	canReg := iop.Form{Basis: iop.Canonical, Layout: iop.Regular}
	wqliop := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.Ql, canReg))
	wqriop := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.Qr, canReg))
	wqmiop := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.Qm, canReg))
	wqoiop := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.Qo, canReg))

	wqkiop := iop.NewWrappedPolynomial(iop.NewPolynomial(qkCompletedCanonical, canReg))
	wqliop.ToLagrangeCoset(&pk.Domain[1])
	wqriop.ToLagrangeCoset(&pk.Domain[1])
	wqmiop.ToLagrangeCoset(&pk.Domain[1])
	wqoiop.ToLagrangeCoset(&pk.Domain[1])
	wqkiop.ToLagrangeCoset(&pk.Domain[1])

	// storing Id
	id := make([]fr.Element, pk.Domain[1].Cardinality)
	id[1].SetOne()
	widiop := iop.NewWrappedPolynomial(iop.NewPolynomial(id, canReg))
	widiop.ToLagrangeCoset(&pk.Domain[1])

	// put the permutations in LagrangeCoset
	ws1 := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.S1Canonical, canReg))
	ws1.ToCanonical(&pk.Domain[0]).ToRegular().ToLagrangeCoset(&pk.Domain[1])

	ws2 := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.S2Canonical, canReg))
	ws2.ToCanonical(&pk.Domain[0]).ToRegular().ToLagrangeCoset(&pk.Domain[1])

	ws3 := iop.NewWrappedPolynomial(iop.NewPolynomial(pk.S3Canonical, canReg))
	ws3.ToCanonical(&pk.Domain[0]).ToRegular().ToLagrangeCoset(&pk.Domain[1])

	// Store z(g*x), without reallocating a slice
	bwsziop := bwziop.ShallowClone().Shift(1)
	bwsziop.ToLagrangeCoset(&pk.Domain[1])

	// L_{g^{0}}
	lone := make([]fr.Element, pk.Domain[0].Cardinality)
	lone[0].SetOne()
	loneiop := iop.NewPolynomial(lone, lagReg)
	wloneiop := iop.NewWrappedPolynomial(loneiop.ToCanonical(&pk.Domain[0]).
		ToRegular().
		ToLagrangeCoset(&pk.Domain[1]))

	// Full capture using latest gnark crypto...
	fic := func(fql, fqr, fqm, fqo, fqk, l, r, o fr.Element) fr.Element {

		var ic, tmp fr.Element

		ic.Mul(&fql, &l)
		tmp.Mul(&fqr, &r)
		ic.Add(&ic, &tmp)
		tmp.Mul(&fqm, &l).Mul(&tmp, &r)
		ic.Add(&ic, &tmp)
		tmp.Mul(&fqo, &o)
		ic.Add(&ic, &tmp).Add(&ic, &fqk)

		return ic
	}

	fo := func(l, r, o, fid, fs1, fs2, fs3, fz, fzs fr.Element) fr.Element {
		var uu fr.Element
		u := pk.Domain[0].FrMultiplicativeGen
		uu.Mul(&u, &u)

		var a, b, tmp fr.Element
		a.Mul(&beta, &fid).Add(&a, &l).Add(&a, &gamma)
		tmp.Mul(&beta, &u).Mul(&tmp, &fid).Add(&tmp, &r).Add(&tmp, &gamma)
		a.Mul(&a, &tmp)
		tmp.Mul(&beta, &uu).Mul(&tmp, &fid).Add(&tmp, &o).Add(&tmp, &gamma)
		a.Mul(&a, &tmp).Mul(&a, &fz)

		b.Mul(&beta, &fs1).Add(&b, &l).Add(&b, &gamma)
		tmp.Mul(&beta, &fs2).Add(&tmp, &r).Add(&tmp, &gamma)
		b.Mul(&b, &tmp)
		tmp.Mul(&beta, &fs3).Add(&tmp, &o).Add(&tmp, &gamma)
		b.Mul(&b, &tmp).Mul(&b, &fzs)

		b.Sub(&b, &a)

		return b
	}

	fone := func(fz, flone fr.Element) fr.Element {
		one := fr.One()
		one.Sub(&fz, &one).Mul(&one, &flone)
		return one
	}

	// 0 , 1,  2,  3,  4,  5,  6, 7,  8,  9, 10, 11, 12, 13, 14
	// l , r , o, id, s1, s2, s3, z, zs, ql, qr, qm, qo, qk,lone
	fm := func(x ...fr.Element) fr.Element {

		a := fic(x[9], x[10], x[11], x[12], x[13], x[0], x[1], x[2])
		b := fo(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8])
		c := fone(x[7], x[14])

		c.Mul(&c, &alpha).Add(&c, &b).Mul(&c, &alpha).Add(&c, &a)

		return c
	}
	testEval, err := iop.Evaluate(fm, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse},
		bwliop,
		bwriop,
		bwoiop,
		widiop,
		ws1,
		ws2,
		ws3,
		bwziop,
		bwsziop,
		wqliop,
		wqriop,
		wqmiop,
		wqoiop,
		wqkiop,
		wloneiop,
	)
	if err != nil {
		return nil, err
	}
	h, err := iop.DivideByXMinusOne(testEval, [2]*fft.Domain{&pk.Domain[0], &pk.Domain[1]})
	if err != nil {
		return nil, err
	}

	// compute kzg commitments of h1, h2 and h3
	if err := commitToQuotient(
		h.Coefficients[:pk.Domain[0].Cardinality+2],
		h.Coefficients[pk.Domain[0].Cardinality+2:2*(pk.Domain[0].Cardinality+2)],
		h.Coefficients[2*(pk.Domain[0].Cardinality+2):3*(pk.Domain[0].Cardinality+2)],
		proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	// derive zeta
	zeta, err := deriveRandomness(&fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	// compute evaluations of (blinded version of) l, r, o, z at zeta
	var blzeta, brzeta, bozeta fr.Element

	var wgEvals sync.WaitGroup
	wgEvals.Add(3)

	go func() {
		bwliop.ToCanonical(&pk.Domain[1]).ToRegular()
		blzeta = bwliop.Evaluate(zeta)
		wgEvals.Done()
	}()

	go func() {
		bwriop.ToCanonical(&pk.Domain[1]).ToRegular()
		brzeta = bwriop.Evaluate(zeta)
		wgEvals.Done()
	}()

	go func() {
		bwoiop.ToCanonical(&pk.Domain[1]).ToRegular()
		bozeta = bwoiop.Evaluate(zeta)
		wgEvals.Done()
	}()

	// open blinded Z at zeta*z
	bwziop.ToCanonical(&pk.Domain[1]).ToRegular()
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &pk.Vk.Generator)
	proof.ZShiftedOpening, err = kzg.Open(
		bwziop.Coefficients[:bwziop.BlindedSize()],
		zetaShifted,
		pk.Vk.KZGSRS,
	)
	if err != nil {
		return nil, err
	}

	// blinded z evaluated at u*zeta
	bzuzeta := proof.ZShiftedOpening.ClaimedValue

	var (
		linearizedPolynomialCanonical []fr.Element
		linearizedPolynomialDigest    curve.G1Affine
		errLPoly                      error
	)

	wgEvals.Wait() // wait for the evaluations

	// compute the linearization polynomial r at zeta
	// (goal: save committing separately to z, ql, qr, qm, qo, k
	linearizedPolynomialCanonical = computeLinearizedPolynomial(
		blzeta,
		brzeta,
		bozeta,
		alpha,
		beta,
		gamma,
		zeta,
		bzuzeta,
		bwziop.Coefficients[:bwziop.BlindedSize()],
		pk,
	)

	// TODO this commitment is only necessary to derive the challenge, we should
	// be able to avoid doing it and get the challenge in another way
	linearizedPolynomialDigest, errLPoly = kzg.Commit(linearizedPolynomialCanonical, pk.Vk.KZGSRS)

	// foldedHDigest = Comm(h1) + ζᵐ⁺²*Comm(h2) + ζ²⁽ᵐ⁺²⁾*Comm(h3)
	var bZetaPowerm, bSize big.Int
	bSize.SetUint64(pk.Domain[0].Cardinality + 2) // +2 because of the masking (h of degree 3(n+2)-1)
	var zetaPowerm fr.Element
	zetaPowerm.Exp(zeta, &bSize)
	zetaPowerm.BigInt(&bZetaPowerm)
	foldedHDigest := proof.H[2]
	foldedHDigest.ScalarMultiplication(&foldedHDigest, &bZetaPowerm)
	foldedHDigest.Add(&foldedHDigest, &proof.H[1])                   // ζᵐ⁺²*Comm(h3)
	foldedHDigest.ScalarMultiplication(&foldedHDigest, &bZetaPowerm) // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2)
	foldedHDigest.Add(&foldedHDigest, &proof.H[0])                   // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2) + Comm(h1)

	// foldedH = h1 + ζ*h2 + ζ²*h3
	foldedH := h.Coefficients[2*(pk.Domain[0].Cardinality+2) : 3*(pk.Domain[0].Cardinality+2)]
	h2 := h.Coefficients[pk.Domain[0].Cardinality+2 : 2*(pk.Domain[0].Cardinality+2)]
	h1 := h.Coefficients[:pk.Domain[0].Cardinality+2]
	utils.Parallelize(len(foldedH), func(start, end int) {
		for i := start; i < end; i++ {
			foldedH[i].Mul(&foldedH[i], &zetaPowerm) // ζᵐ⁺²*h3
			foldedH[i].Add(&foldedH[i], &h2[i])      // ζ^{m+2)*h3+h2
			foldedH[i].Mul(&foldedH[i], &zetaPowerm) // ζ²⁽ᵐ⁺²⁾*h3+h2*ζᵐ⁺²
			foldedH[i].Add(&foldedH[i], &h1[i])      // ζ^{2(m+2)*h3+ζᵐ⁺²*h2 + h1
		}
	})

	if errLPoly != nil {
		return nil, errLPoly
	}

	// Batch open the first list of polynomials
	proof.BatchedProof, err = kzg.BatchOpenSinglePoint(
		[][]fr.Element{
			foldedH,
			linearizedPolynomialCanonical,
			bwliop.Coefficients[:bwliop.BlindedSize()],
			bwriop.Coefficients[:bwriop.BlindedSize()],
			bwoiop.Coefficients[:bwoiop.BlindedSize()],
			pk.S1Canonical,
			pk.S2Canonical,
		},
		[]kzg.Digest{
			foldedHDigest,
			linearizedPolynomialDigest,
			proof.LRO[0],
			proof.LRO[1],
			proof.LRO[2],
			pk.Vk.S[0],
			pk.Vk.S[1],
		},
		zeta,
		hFunc,
		pk.Vk.KZGSRS,
	)

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	if err != nil {
		return nil, err
	}

	return proof, nil

}

// fills proof.LRO with kzg commits of bcl, bcr and bco
func commitToLRO(bcl, bcr, bco []fr.Element, proof *Proof, srs *kzg.SRS) error {
	n := runtime.NumCPU() / 2
	var err0, err1, err2 error
	chCommit0 := make(chan struct{}, 1)
	chCommit1 := make(chan struct{}, 1)
	go func() {
		proof.LRO[0], err0 = kzg.Commit(bcl, srs, n)
		close(chCommit0)
	}()
	go func() {
		proof.LRO[1], err1 = kzg.Commit(bcr, srs, n)
		close(chCommit1)
	}()
	if proof.LRO[2], err2 = kzg.Commit(bco, srs, n); err2 != nil {
		return err2
	}
	<-chCommit0
	<-chCommit1

	if err0 != nil {
		return err0
	}

	return err1
}

func commitToQuotient(h1, h2, h3 []fr.Element, proof *Proof, srs *kzg.SRS) error {
	n := runtime.NumCPU() / 2
	var err0, err1, err2 error
	chCommit0 := make(chan struct{}, 1)
	chCommit1 := make(chan struct{}, 1)
	go func() {
		proof.H[0], err0 = kzg.Commit(h1, srs, n)
		close(chCommit0)
	}()
	go func() {
		proof.H[1], err1 = kzg.Commit(h2, srs, n)
		close(chCommit1)
	}()
	if proof.H[2], err2 = kzg.Commit(h3, srs, n); err2 != nil {
		return err2
	}
	<-chCommit0
	<-chCommit1

	if err0 != nil {
		return err0
	}

	return err1
}

// evaluateLROSmallDomain extracts the solution l, r, o, and returns it in lagrange form.
// solution = [ public | secret | internal ]
func evaluateLROSmallDomain(spr *cs.SparseR1CS, pk *ProvingKey, solution []fr.Element) ([]fr.Element, []fr.Element, []fr.Element) {

	s := int(pk.Domain[0].Cardinality)

	var l, r, o []fr.Element
	l = make([]fr.Element, s)
	r = make([]fr.Element, s)
	o = make([]fr.Element, s)
	s0 := solution[0]

	for i := 0; i < len(spr.Public); i++ { // placeholders
		l[i] = solution[i]
		r[i] = s0
		o[i] = s0
	}
	offset := len(spr.Public)
	for i := 0; i < len(spr.Constraints); i++ { // constraints
		l[offset+i] = solution[spr.Constraints[i].L.WireID()]
		r[offset+i] = solution[spr.Constraints[i].R.WireID()]
		o[offset+i] = solution[spr.Constraints[i].O.WireID()]
	}
	offset += len(spr.Constraints)

	for i := 0; i < s-offset; i++ { // offset to reach 2**n constraints (where the id of l,r,o is 0, so we assign solution[0])
		l[offset+i] = s0
		r[offset+i] = s0
		o[offset+i] = s0
	}

	return l, r, o

}

// computeLinearizedPolynomial computes the linearized polynomial in canonical basis.
// The purpose is to commit and open all in one ql, qr, qm, qo, qk.
// * lZeta, rZeta, oZeta are the evaluation of l, r, o at zeta
// * z is the permutation polynomial, zu is Z(μX), the shifted version of Z
// * pk is the proving key: the linearized polynomial is a linear combination of ql, qr, qm, qo, qk.
//
// The Linearized polynomial is:
//
// α²*L₁(ζ)*Z(X)
// + α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ))
// + l(ζ)*Ql(X) + l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X)
func computeLinearizedPolynomial(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, blindedZCanonical []fr.Element, pk *ProvingKey) []fr.Element {

	// first part: individual constraints
	var rl fr.Element
	rl.Mul(&rZeta, &lZeta)

	// second part:
	// Z(μζ)(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*s3(X)-Z(X)(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ)
	var s1, s2 fr.Element
	chS1 := make(chan struct{}, 1)
	go func() {
		ps1 := iop.NewPolynomial(pk.S1Canonical, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
		s1 = ps1.Evaluate(zeta)                              // s1(ζ)
		s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma) // (l(ζ)+β*s1(ζ)+γ)
		close(chS1)
	}()
	ps2 := iop.NewPolynomial(pk.S2Canonical, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	tmp := ps2.Evaluate(zeta)                                // s2(ζ)
	tmp.Mul(&tmp, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma) // (r(ζ)+β*s2(ζ)+γ)
	<-chS1
	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta) // (l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)

	var uzeta, uuzeta fr.Element
	uzeta.Mul(&zeta, &pk.Vk.CosetShift)
	uuzeta.Mul(&uzeta, &pk.Vk.CosetShift)

	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)      // (l(ζ)+β*ζ+γ)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)  // (r(ζ)+β*u*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma) // (o(ζ)+β*u²*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	s2.Neg(&s2)                                                 // -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

	// third part L₁(ζ)*α²*Z
	var lagrangeZeta, one, den, frNbElmt fr.Element
	one.SetOne()
	nbElmt := int64(pk.Domain[0].Cardinality)
	lagrangeZeta.Set(&zeta).
		Exp(lagrangeZeta, big.NewInt(nbElmt)).
		Sub(&lagrangeZeta, &one)
	frNbElmt.SetUint64(uint64(nbElmt))
	den.Sub(&zeta, &one).
		Inverse(&den)
	lagrangeZeta.Mul(&lagrangeZeta, &den). // L₁ = (ζⁿ⁻¹)/(ζ-1)
						Mul(&lagrangeZeta, &alpha).
						Mul(&lagrangeZeta, &alpha).
						Mul(&lagrangeZeta, &pk.Domain[0].CardinalityInv) // (1/n)*α²*L₁(ζ)

	linPol := make([]fr.Element, len(blindedZCanonical))
	copy(linPol, blindedZCanonical)

	utils.Parallelize(len(linPol), func(start, end int) {

		var t0, t1 fr.Element

		for i := start; i < end; i++ {

			linPol[i].Mul(&linPol[i], &s2) // -Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

			if i < len(pk.S3Canonical) {

				t0.Mul(&pk.S3Canonical[i], &s1) // (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*β*s3(X)

				linPol[i].Add(&linPol[i], &t0)
			}

			linPol[i].Mul(&linPol[i], &alpha) // α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ))

			if i < len(pk.Qm) {

				t1.Mul(&pk.Qm[i], &rl) // linPol = linPol + l(ζ)r(ζ)*Qm(X)
				t0.Mul(&pk.Ql[i], &lZeta)
				t0.Add(&t0, &t1)
				linPol[i].Add(&linPol[i], &t0) // linPol = linPol + l(ζ)*Ql(X)

				t0.Mul(&pk.Qr[i], &rZeta)
				linPol[i].Add(&linPol[i], &t0) // linPol = linPol + r(ζ)*Qr(X)

				t0.Mul(&pk.Qo[i], &oZeta).Add(&t0, &pk.CQk[i])
				linPol[i].Add(&linPol[i], &t0) // linPol = linPol + o(ζ)*Qo(X) + Qk(X)
			}

			t0.Mul(&blindedZCanonical[i], &lagrangeZeta)
			linPol[i].Add(&linPol[i], &t0) // finish the computation
		}
	})
	return linPol
}
