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
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"

	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"

	cs "github.com/consensys/gnark/constraint/bn254"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
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

func printVector(n string, v []fr.Element) {
	fmt.Printf("%s = [", n)
	for i := 0; i < len(v); i++ {
		fmt.Printf("Fr(%s),", v[i].String())
	}
	fmt.Println("]")
}

func printLayout(f iop.Form) {
	if f.Basis == iop.Canonical {
		fmt.Println("CANONICAL")
	} else if f.Basis == iop.Lagrange {
		fmt.Println("LAGRANGE")
	} else {
		fmt.Println("LAGRANGECOSET")
	}
	if f.Layout == iop.Regular {
		fmt.Println("REGULAR")
	} else {
		fmt.Println("BITREVERSE")
	}
}

// Prove from the public data
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness bn254witness.Witness, opt backend.ProverConfig) (*Proof, error) {

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

	// save ll, lr, lo, and make a copy of them in canonical basis.
	// note that we allocate more capacity to reuse for blinded polynomials
	blindedLCanonical, blindedRCanonical, blindedOCanonical, err := computeBlindedLROCanonical(
		evaluationLDomainSmall,
		evaluationRDomainSmall,
		evaluationODomainSmall,
		&pk.Domain[0])
	if err != nil {
		return nil, err
	}

	// compute kzg commitments of bcl, bcr and bco
	if err := commitToLRO(blindedLCanonical, blindedRCanonical, blindedOCanonical, proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	// The first challenge is derived using the public data: the commitments to the permutation,
	// the coefficients of the circuit, and the public inputs.
	// derive gamma from the Comm(blinded cl), Comm(blinded cr), Comm(blinded co)
	if err := bindPublicData(&fs, "gamma", *pk.Vk, fullWitness[:len(spr.Public)]); err != nil {
		return nil, err
	}
	bgamma, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return nil, err
	}
	var gamma fr.Element
	gamma.SetBytes(bgamma)

	// Fiat Shamir this
	beta, err := deriveRandomness(&fs, "beta")
	if err != nil {
		return nil, err
	}

	// ----- [ IOP VERSION ] -----
	beta.SetString("509122406974049427960843098167218400516211819804489628145814565771242591360")
	gamma.SetString("1061346473205166015233790408627689156038137545206111856192296068827881251425")
	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	liop := iop.Polynomial{Coefficients: evaluationLDomainSmall, Form: lagReg}
	riop := iop.Polynomial{Coefficients: evaluationRDomainSmall, Form: lagReg}
	oiop := iop.Polynomial{Coefficients: evaluationODomainSmall, Form: lagReg}

	// compute the copy constraint's ratio
	ziop, err := iop.BuildRatioCopyConstraint(
		[]iop.Polynomial{liop, riop, oiop},
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
	// note that we explicitly double the number of tasks for the multi exp in kzg.Commit
	// this may add additional arithmetic operations, but with smaller tasks
	// we ensure that this commitment is well parallelized, without having a "unbalanced task" making
	// the rest of the code wait too long.
	proof.Z, err = kzg.Commit(ziop.Coefficients, pk.Vk.KZGSRS, runtime.NumCPU()*2)
	if err != nil {
		return proof, err
	}

	// derive alpha from the Comm(l), Comm(r), Comm(o), Com(Z)
	alpha, err = deriveRandomness(&fs, "alpha", &proof.Z)
	if err != nil {
		return proof, err
	}

	// compute qk in canonical basis, completed with the public inputs
	qkCompletedCanonical := make([]fr.Element, pk.Domain[0].Cardinality)
	copy(qkCompletedCanonical, fullWitness[:len(spr.Public)])
	copy(qkCompletedCanonical[len(spr.Public):], pk.LQk[len(spr.Public):])
	pk.Domain[0].FFTInverse(qkCompletedCanonical, fft.DIF)
	fft.BitReverse(qkCompletedCanonical)

	// evaluate qlL+qrR+qmLR+qoO+qK (l,r,o=x₅,x₆,x₇)
	var constraintsCapture iop.MultivariatePolynomial
	var one fr.Element
	one.SetOne()
	constraintsCapture.AddMonomial(one, []int{1, 0, 0, 0, 0, 1, 0, 0})
	constraintsCapture.AddMonomial(one, []int{0, 1, 0, 0, 0, 0, 1, 0})
	constraintsCapture.AddMonomial(one, []int{0, 0, 1, 0, 0, 1, 1, 0})
	constraintsCapture.AddMonomial(one, []int{0, 0, 0, 1, 0, 0, 0, 1})
	constraintsCapture.AddMonomial(one, []int{0, 0, 0, 0, 1, 0, 0, 0})
	wliop := liop.WrapMe(0)
	wriop := riop.WrapMe(0)
	woiop := oiop.WrapMe(0)
	// printVector("l", wliop.P.Coefficients)
	// printVector("r", wriop.P.Coefficients)
	// printVector("o", woiop.P.Coefficients)
	wliop.ToCanonical(wliop, &pk.Domain[0]).ToRegular(wliop).ToLagrangeCoset(wliop, &pk.Domain[1])
	wriop.ToCanonical(wriop, &pk.Domain[0]).ToRegular(wriop).ToLagrangeCoset(wriop, &pk.Domain[1])
	woiop.ToCanonical(woiop, &pk.Domain[0]).ToRegular(woiop).ToLagrangeCoset(woiop, &pk.Domain[1])
	canReg := iop.Form{Basis: iop.Canonical, Layout: iop.Regular}
	wqliop := iop.NewPolynomial(pk.Ql, canReg).WrapMe(0)
	wqriop := iop.NewPolynomial(pk.Qr, canReg).WrapMe(0)
	wqmiop := iop.NewPolynomial(pk.Qm, canReg).WrapMe(0)
	wqoiop := iop.NewPolynomial(pk.Qo, canReg).WrapMe(0)
	wqkiop := iop.NewPolynomial(qkCompletedCanonical, canReg).WrapMe(0)
	// printVector("ql", wqliop.P.Coefficients)
	// printVector("qr", wqriop.P.Coefficients)
	// printVector("qm", wqmiop.P.Coefficients)
	// printVector("qo", wqoiop.P.Coefficients)
	// printVector("qk", wqkiop.P.Coefficients)
	wqliop.ToLagrangeCoset(wqliop, &pk.Domain[1])
	wqriop.ToLagrangeCoset(wqriop, &pk.Domain[1])
	wqmiop.ToLagrangeCoset(wqmiop, &pk.Domain[1])
	wqoiop.ToLagrangeCoset(wqoiop, &pk.Domain[1])
	wqkiop.ToLagrangeCoset(wqkiop, &pk.Domain[1])

	constraints, err := constraintsCapture.EvaluatePolynomials(
		[]iop.WrappedPolynomial{*wqliop, *wqriop, *wqmiop, *wqoiop, *wqkiop, *wliop, *wriop, *woiop},
	)
	if err != nil {
		return proof, err
	} // -> CORRECT

	// constraints ordering
	var subOrderingCapture [3]iop.MultivariatePolynomial
	var ubeta, uubeta fr.Element
	ubeta.Mul(&beta, &pk.Domain[0].FrMultiplicativeGen)
	uubeta.Mul(&ubeta, &pk.Domain[0].FrMultiplicativeGen)
	subOrderingCapture[0].AddMonomial(one, []int{1, 0})
	subOrderingCapture[0].AddMonomial(beta, []int{0, 1})
	subOrderingCapture[0].C.Set(&gamma)
	subOrderingCapture[1].AddMonomial(one, []int{1, 0})
	subOrderingCapture[1].AddMonomial(ubeta, []int{0, 1})
	subOrderingCapture[1].C.Set(&gamma)
	subOrderingCapture[2].AddMonomial(one, []int{1, 0})
	subOrderingCapture[2].AddMonomial(uubeta, []int{0, 1})
	subOrderingCapture[2].C.Set(&gamma)

	// ql+β*x+γ
	id := make([]fr.Element, pk.Domain[1].Cardinality)
	id[1].SetOne()
	widiop := iop.NewPolynomial(id, canReg).WrapMe(0)
	widiop.ToLagrangeCoset(widiop, &pk.Domain[1])
	a, err := subOrderingCapture[0].EvaluatePolynomials([]iop.WrappedPolynomial{*wliop, *widiop})
	if err != nil {
		return proof, err
	}
	wa := a.WrapMe(0) // -> CORRECT

	// qr+β*ν*x+γ
	b, err := subOrderingCapture[1].EvaluatePolynomials([]iop.WrappedPolynomial{*wriop, *widiop})
	if err != nil {
		return proof, err
	}
	wb := b.WrapMe(0) // -> CORRECT

	// qo+β*ν²*x+γ
	c, err := subOrderingCapture[2].EvaluatePolynomials([]iop.WrappedPolynomial{*woiop, *widiop})
	if err != nil {
		return proof, err
	}
	wc := c.WrapMe(0) // -> CORRECT

	// ql+β*σ₁+γ
	ws1 := iop.NewPolynomial(pk.S1Canonical, canReg).WrapMe(0)
	// printVector("s1", ws1.P.Coefficients)
	ws1.ToCanonical(ws1, &pk.Domain[0]).ToRegular(ws1).ToLagrangeCoset(ws1, &pk.Domain[1])
	u, err := subOrderingCapture[0].EvaluatePolynomials([]iop.WrappedPolynomial{*wliop, *ws1})
	if err != nil {
		return proof, err
	}
	wu := u.WrapMe(0) // -> CORRECT

	// qr+β*σ₂+γ
	ws2 := iop.NewPolynomial(pk.S2Canonical, canReg).WrapMe(0)
	// printVector("s2", ws2.P.Coefficients)
	ws2.ToCanonical(ws2, &pk.Domain[0]).ToRegular(ws2).ToLagrangeCoset(ws2, &pk.Domain[1])
	v, err := subOrderingCapture[0].EvaluatePolynomials([]iop.WrappedPolynomial{*wriop, *ws2})
	if err != nil {
		return proof, err
	}
	wv := v.WrapMe(0) // -> CORRECT

	// qo+β*σ₃+γ
	ws3 := iop.NewPolynomial(pk.S3Canonical, canReg).WrapMe(0)
	// printVector("s3", ws3.P.Coefficients)
	ws3.ToCanonical(ws3, &pk.Domain[0]).ToRegular(ws3).ToLagrangeCoset(ws3, &pk.Domain[1])
	w, err := subOrderingCapture[0].EvaluatePolynomials([]iop.WrappedPolynomial{*woiop, *ws3})
	if err != nil {
		return proof, err
	}
	ww := w.WrapMe(0) // -> CORRECT

	// Z(ωX)(ql+β*σ₁+γ)(ql+β*σ₂+γ)(ql+β*σ₃+γ)-
	// Z(ql+βX+γ)(ql+β*νX+γ)(ql+β*ν²X+γ)
	var orderingCapture iop.MultivariatePolynomial
	var minusOne fr.Element
	wziop := ziop.WrapMe(0)
	wsziop := ziop.WrapMe(1)
	wsziop.ToCanonical(wsziop, &pk.Domain[0]).ToRegular(wsziop).ToLagrangeCoset(wsziop, &pk.Domain[1])
	minusOne.Neg(&one)
	orderingCapture.AddMonomial(one, []int{1, 1, 1, 1, 0, 0, 0, 0})
	orderingCapture.AddMonomial(minusOne, []int{0, 0, 0, 0, 1, 1, 1, 1})
	ordering, err := orderingCapture.EvaluatePolynomials(
		[]iop.WrappedPolynomial{*wsziop, *wu, *wv, *ww, *wziop, *wa, *wb, *wc})
	if err != nil {
		return proof, err
	}

	// L_{0}(z-1)
	lone := make([]fr.Element, pk.Domain[0].Cardinality)
	lone[0].SetOne()
	loneiop := iop.NewPolynomial(lone, lagReg)
	wloneiop := loneiop.ToCanonical(loneiop, &pk.Domain[0]).
		ToRegular(loneiop).
		ToLagrangeCoset(loneiop, &pk.Domain[1]).
		WrapMe(0)
	var startsAtOneCapture iop.MultivariatePolynomial
	startsAtOneCapture.AddMonomial(one, []int{1, 1})
	startsAtOneCapture.AddMonomial(minusOne, []int{0, 1})
	startsAtOne, err := startsAtOneCapture.EvaluatePolynomials(
		[]iop.WrappedPolynomial{*wziop, *wloneiop},
	)
	if err != nil {
		return proof, err
	}

	// bundle everything up
	var plonkCapture iop.MultivariatePolynomial
	var aalpha, aalphaSquared fr.Element
	aalpha.SetString("293729873209832093")
	aalphaSquared.Square(&aalpha)
	plonkCapture.AddMonomial(one, []int{1, 0, 0})
	plonkCapture.AddMonomial(aalpha, []int{0, 1, 0})
	plonkCapture.AddMonomial(aalphaSquared, []int{0, 0, 1})

	wconstraints := constraints.WrapMe(0)
	wordering := ordering.WrapMe(0)
	wstartsAtOne := startsAtOne.WrapMe(0)

	h, err := iop.ComputeQuotient(
		[]iop.WrappedPolynomial{*wconstraints, *wordering, *wstartsAtOne},
		plonkCapture,
		[2]*fft.Domain{&pk.Domain[0], &pk.Domain[1]})
	if err != nil {
		return proof, err
	}

	// compute kzg commitments of h1, h2 and h3
	if err := commitToQuotient(
		h.Coefficients[:pk.Domain[0].Cardinality+2],
		h.Coefficients[pk.Domain[0].Cardinality+2:2*(pk.Domain[0].Cardinality+2)],
		h.Coefficients[2*(pk.Domain[0].Cardinality+2):],
		proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	// derive zeta
	zeta, err := deriveRandomness(&fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	// ---------------------------

	// compute Z, the permutation accumulator polynomial, in canonical basis
	// ll, lr, lo are NOT blinded
	var blindedZCanonical []fr.Element
	chZ := make(chan error, 1)
	var alpha fr.Element
	go func() {
		var err error
		blindedZCanonical, err = computeBlindedZCanonical(
			evaluationLDomainSmall,
			evaluationRDomainSmall,
			evaluationODomainSmall,
			pk, beta, gamma)
		if err != nil {
			chZ <- err
			close(chZ)
			return
		}

		// // commit to the blinded version of z
		// // note that we explicitly double the number of tasks for the multi exp in kzg.Commit
		// // this may add additional arithmetic operations, but with smaller tasks
		// // we ensure that this commitment is well parallelized, without having a "unbalanced task" making
		// // the rest of the code wait too long.
		// if proof.Z, err = kzg.Commit(blindedZCanonical, pk.Vk.KZGSRS, runtime.NumCPU()*2); err != nil {
		// 	chZ <- err
		// 	close(chZ)
		// 	return
		// }

		// // derive alpha from the Comm(l), Comm(r), Comm(o), Com(Z)
		// alpha, err = deriveRandomness(&fs, "alpha", &proof.Z)
		chZ <- err
		close(chZ)
	}()

	// evaluation of the blinded versions of l, r, o and bz
	// on the coset of the big domain
	var (
		evaluationBlindedLDomainBigBitReversed []fr.Element
		evaluationBlindedRDomainBigBitReversed []fr.Element
		evaluationBlindedODomainBigBitReversed []fr.Element
		evaluationBlindedZDomainBigBitReversed []fr.Element
	)
	chEvalBL := make(chan struct{}, 1)
	chEvalBR := make(chan struct{}, 1)
	chEvalBO := make(chan struct{}, 1)
	go func() {
		evaluationBlindedLDomainBigBitReversed = evaluateDomainBigBitReversed(blindedLCanonical, &pk.Domain[1])
		close(chEvalBL)
	}()
	go func() {
		evaluationBlindedRDomainBigBitReversed = evaluateDomainBigBitReversed(blindedRCanonical, &pk.Domain[1])
		close(chEvalBR)
	}()
	go func() {
		evaluationBlindedODomainBigBitReversed = evaluateDomainBigBitReversed(blindedOCanonical, &pk.Domain[1])
		close(chEvalBO)
	}()

	var constraintsInd, constraintsOrdering []fr.Element
	chConstraintInd := make(chan struct{}, 1)
	go func() {

		// compute qk in canonical basis, completed with the public inputs
		qkCompletedCanonical := make([]fr.Element, pk.Domain[0].Cardinality)
		copy(qkCompletedCanonical, fullWitness[:len(spr.Public)])
		copy(qkCompletedCanonical[len(spr.Public):], pk.LQk[len(spr.Public):])
		pk.Domain[0].FFTInverse(qkCompletedCanonical, fft.DIF)
		fft.BitReverse(qkCompletedCanonical)

		// compute the evaluation of qlL+qrR+qmL.R+qoO+k on the coset of the big domain
		// → uses the blinded version of l, r, o
		<-chEvalBL
		<-chEvalBR
		<-chEvalBO
		constraintsInd = evaluateConstraintsDomainBigBitReversed(
			pk,
			evaluationBlindedLDomainBigBitReversed,
			evaluationBlindedRDomainBigBitReversed,
			evaluationBlindedODomainBigBitReversed,
			qkCompletedCanonical)
		close(chConstraintInd)
	}()

	chConstraintOrdering := make(chan error, 1)
	go func() {
		if err := <-chZ; err != nil {
			chConstraintOrdering <- err
			return
		}

		evaluationBlindedZDomainBigBitReversed = evaluateDomainBigBitReversed(blindedZCanonical, &pk.Domain[1])
		// compute zu*g1*g2*g3-z*f1*f2*f3 on the coset of the big domain
		// evalL, evalO, evalR are the evaluations of the blinded versions of l, r, o.
		<-chEvalBL
		<-chEvalBR
		<-chEvalBO
		constraintsOrdering = evaluateOrderingDomainBigBitReversed(
			pk,
			evaluationBlindedZDomainBigBitReversed,
			evaluationBlindedLDomainBigBitReversed,
			evaluationBlindedRDomainBigBitReversed,
			evaluationBlindedODomainBigBitReversed,
			beta,
			gamma)
		chConstraintOrdering <- nil
		close(chConstraintOrdering)
	}()

	if err := <-chConstraintOrdering; err != nil {
		return nil, err
	}

	<-chConstraintInd

	// compute h in canonical form
	h1, h2, h3 := computeQuotientCanonical(pk, constraintsInd, constraintsOrdering, evaluationBlindedZDomainBigBitReversed, alpha)

	// compute kzg commitments of h1, h2 and h3
	if err := commitToQuotient(h1, h2, h3, proof, pk.Vk.KZGSRS); err != nil {
		return nil, err
	}

	// derive zeta
	zeta, err := deriveRandomness(&fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	// compute evaluations of (blinded version of) l, r, o, z at zeta
	var blzeta, brzeta, bozeta fr.Element
	var wgZetaEvals sync.WaitGroup
	wgZetaEvals.Add(3)
	go func() {
		blzeta = eval(blindedLCanonical, zeta)
		wgZetaEvals.Done()
	}()
	go func() {
		brzeta = eval(blindedRCanonical, zeta)
		wgZetaEvals.Done()
	}()
	go func() {
		bozeta = eval(blindedOCanonical, zeta)
		wgZetaEvals.Done()
	}()

	// open blinded Z at zeta*z
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &pk.Vk.Generator)
	proof.ZShiftedOpening, err = kzg.Open(
		blindedZCanonical,
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
	chLpoly := make(chan struct{}, 1)

	go func() {
		// compute the linearization polynomial r at zeta (goal: save committing separately to z, ql, qr, qm, qo, k)
		wgZetaEvals.Wait()
		linearizedPolynomialCanonical = computeLinearizedPolynomial(
			blzeta,
			brzeta,
			bozeta,
			alpha,
			beta,
			gamma,
			zeta,
			bzuzeta,
			blindedZCanonical,
			pk,
		)

		// TODO this commitment is only necessary to derive the challenge, we should
		// be able to avoid doing it and get the challenge in another way
		linearizedPolynomialDigest, errLPoly = kzg.Commit(linearizedPolynomialCanonical, pk.Vk.KZGSRS)
		close(chLpoly)
	}()

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
	foldedH := h3
	utils.Parallelize(len(foldedH), func(start, end int) {
		for i := start; i < end; i++ {
			foldedH[i].Mul(&foldedH[i], &zetaPowerm) // ζᵐ⁺²*h3
			foldedH[i].Add(&foldedH[i], &h2[i])      // ζ^{m+2)*h3+h2
			foldedH[i].Mul(&foldedH[i], &zetaPowerm) // ζ²⁽ᵐ⁺²⁾*h3+h2*ζᵐ⁺²
			foldedH[i].Add(&foldedH[i], &h1[i])      // ζ^{2(m+2)*h3+ζᵐ⁺²*h2 + h1
		}
	})

	<-chLpoly
	if errLPoly != nil {
		return nil, errLPoly
	}

	// Batch open the first list of polynomials
	proof.BatchedProof, err = kzg.BatchOpenSinglePoint(
		[][]fr.Element{
			foldedH,
			linearizedPolynomialCanonical,
			blindedLCanonical,
			blindedRCanonical,
			blindedOCanonical,
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

// eval evaluates c at p
func eval(c []fr.Element, p fr.Element) fr.Element {
	var r fr.Element
	for i := len(c) - 1; i >= 0; i-- {
		r.Mul(&r, &p).Add(&r, &c[i])
	}
	return r
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

// computeBlindedLROCanonical l, r, o in canonical basis with blinding
func computeBlindedLROCanonical(ll, lr, lo []fr.Element, domain *fft.Domain) (bcl, bcr, bco []fr.Element, err error) {

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
		// if _, err := blindingPoly[i].SetRandom(); err != nil {
		// 	return nil, err
		// }
		blindingPoly[i].SetZero()
	}

	// blinding
	for i := uint64(0); i < bo+1; i++ {
		res[i].Sub(&res[i], &blindingPoly[i])
		res[rou+i].Add(&res[rou+i], &blindingPoly[i])
	}

	return res, nil

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

// computeZ computes Z, in canonical basis, where:
//
//   - Z of degree n (domainNum.Cardinality)
//
//   - Z(1)=1
//     (l(g^k)+β*g^k+γ)*(r(g^k)+uβ*g^k+γ)*(o(g^k)+u²β*g^k+γ)
//
//   - for i>0: Z(gⁱ) = Π_{k<i} -------------------------------------------------------
//     (l(g^k)+β*s1(g^k)+γ)*(r(g^k)+β*s2(g^k)+γ)*(o(g^k)+β*s3(\g^k)+γ)
//
//   - l, r, o are the solution in Lagrange basis, evaluated on the small domain
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

// evaluateConstraintsDomainBigBitReversed computes the evaluation of lL+qrR+qqmL.R+qoO+k on
// the big domain coset.
//
// * evalL, evalR, evalO are the evaluation of the blinded solution vectors on odd cosets
// * qk is the completed version of qk, in canonical version
func evaluateConstraintsDomainBigBitReversed(pk *ProvingKey, evalL, evalR, evalO, qk []fr.Element) []fr.Element {
	var evalQl, evalQr, evalQm, evalQo, evalQk []fr.Element
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		evalQl = evaluateDomainBigBitReversed(pk.Ql, &pk.Domain[1])
		wg.Done()
	}()
	go func() {
		evalQr = evaluateDomainBigBitReversed(pk.Qr, &pk.Domain[1])
		wg.Done()
	}()
	go func() {
		evalQm = evaluateDomainBigBitReversed(pk.Qm, &pk.Domain[1])
		wg.Done()
	}()
	go func() {
		evalQo = evaluateDomainBigBitReversed(pk.Qo, &pk.Domain[1])
		wg.Done()
	}()
	evalQk = evaluateDomainBigBitReversed(qk, &pk.Domain[1])
	wg.Wait()

	// computes the evaluation of qrR+qlL+qmL.R+qoO+k on the coset of the big domain
	utils.Parallelize(len(evalQk), func(start, end int) {
		var t0, t1 fr.Element
		for i := start; i < end; i++ {
			t1.Mul(&evalQm[i], &evalR[i]) // qm.r
			t1.Add(&t1, &evalQl[i])       // qm.r + ql
			t1.Mul(&t1, &evalL[i])        //  qm.l.r + ql.l

			t0.Mul(&evalQr[i], &evalR[i])
			t0.Add(&t0, &t1) // qm.l.r + ql.l + qr.r

			t1.Mul(&evalQo[i], &evalO[i])
			t0.Add(&t0, &t1)               // ql.l + qr.r + qm.l.r + qo.o
			evalQk[i].Add(&t0, &evalQk[i]) // ql.l + qr.r + qm.l.r + qo.o + k
		}
	})

	return evalQk
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
	res := make([]fr.Element, pk.Domain[1].Cardinality)

	nn := uint64(64 - bits.TrailingZeros64(uint64(nbElmts)))

	// needed to shift evalZ
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

			g[0].Mul(&pk.EvaluationPermutationBigDomainBitReversed[_i], &beta).Add(&g[0], &l[_i]).Add(&g[0], &gamma)                //l(gⁱ))+s1(gⁱ)*β+γ
			g[1].Mul(&pk.EvaluationPermutationBigDomainBitReversed[int(_i)+nbElmts], &beta).Add(&g[1], &r[_i]).Add(&g[1], &gamma)   //r(gⁱ))+s2(gⁱ)*β+γ
			g[2].Mul(&pk.EvaluationPermutationBigDomainBitReversed[int(_i)+2*nbElmts], &beta).Add(&g[2], &o[_i]).Add(&g[2], &gamma) //o(gⁱ))+s3(gⁱ)*β+γ

			f[0].Mul(&f[0], &f[1]).Mul(&f[0], &f[2]).Mul(&f[0], &z[_i])  // z(gⁱ)*(l(gⁱ)+g^i*β+γ)*(r(g^i)+u*g^i*β+γ)*(o(g^i)+u²*g^i*β+γ)
			g[0].Mul(&g[0], &g[1]).Mul(&g[0], &g[2]).Mul(&g[0], &z[_is]) //  z_(ugⁱ)*(l(gⁱ))+s₁(gⁱ)*β+γ)*(r(gⁱ))+s₂(gⁱ)*β+γ)*(o(gⁱ))+s₃(gⁱ)*β+γ)

			res[_i].Sub(&g[0], &f[0]) // z_(ugⁱ)*(l(gⁱ))+s₁(gⁱ)*β+γ)*(r(gⁱ))+s₂(gⁱ)*β+γ)*(o(gⁱ))+s₃(gⁱ)*β+γ) - z(gⁱ)*(l(gⁱ)+g^i*β+γ)*(r(g^i)+u*g^i*β+γ)*(o(g^i)+u²*g^i*β+γ)

			evaluationIDBigDomain.Mul(&evaluationIDBigDomain, &pk.Domain[1].Generator) // gⁱ*g
		}
	})

	return res
}

// evaluateDomainBigBitReversed evaluates poly (canonical form) of degree m<n where n=domainH.Cardinality
// on the big domain (coset).
//
// Puts the result in res of size n.
// Warning: result is in bit reversed order, we do a bit reverse operation only once in computeQuotientCanonical
func evaluateDomainBigBitReversed(poly []fr.Element, domainH *fft.Domain) []fr.Element {
	res := make([]fr.Element, domainH.Cardinality)
	copy(res, poly)
	domainH.FFT(res, fft.DIF, true)
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
// ql(X)L(X)+qr(X)R(X)+qm(X)L(X)R(X)+qo(X)O(X)+k(X) + α.(z(μX)*g₁(X)*g₂(X)*g₃(X)-z(X)*f₁(X)*f₂(X)*f₃(X)) + α²*L₁(X)*(Z(X)-1)= h(X)Z(X)
//
// constraintInd, constraintOrdering are evaluated on the big domain (coset).
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
	pk.Domain[1].FFT(startsAtOne, fft.DIF, true)

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
			h[_i].Mul(&startsAtOne[_i], &alpha).Mul(&h[_i], &t).
				Add(&h[_i], &evaluationConstraintOrderingBitReversed[_i]).
				Mul(&h[_i], &alpha).
				Add(&h[_i], &evaluationConstraintsIndBitReversed[_i]).
				Mul(&h[_i], &evaluationXnMinusOneInverse[i%ratio])
		}
	})

	// put h in canonical form. h is of degree 3*(n+1)+2.
	// using fft.DIT put h revert bit reverse
	pk.Domain[1].FFTInverse(h, fft.DIT, true)

	// degree of hi is n+2 because of the blinding
	h1 := h[:pk.Domain[0].Cardinality+2]
	h2 := h[pk.Domain[0].Cardinality+2 : 2*(pk.Domain[0].Cardinality+2)]
	h3 := h[2*(pk.Domain[0].Cardinality+2) : 3*(pk.Domain[0].Cardinality+2)]

	return h1, h2, h3

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
		s1 = eval(pk.S1Canonical, zeta)                      // s1(ζ)
		s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma) // (l(ζ)+β*s1(ζ)+γ)
		close(chS1)
	}()
	tmp := eval(pk.S2Canonical, zeta)                        // s2(ζ)
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
