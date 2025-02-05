// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	curve "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/mpcsetup"
	gcUtils "github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls24-317"
	"github.com/consensys/gnark/internal/utils"
	"math/big"
	"slices"
	"sync"
)

// Phase2Evaluations components of the circuit keys
// not depending on Phase2 randomisations
type Phase2Evaluations struct { // TODO @Tabaie rename
	G1 struct {
		A   []curve.G1Affine   // A are the left coefficient polynomials for each witness element, evaluated at τ
		B   []curve.G1Affine   // B are the right coefficient polynomials for each witness element, evaluated at τ
		VKK []curve.G1Affine   // VKK are the coefficients of the public witness and commitments
		CKK [][]curve.G1Affine // CKK are the coefficients of the committed values
	}
	G2 struct {
		B []curve.G2Affine // B are the right coefficient polynomials for each witness element, evaluated at τ
	}
	PublicAndCommitmentCommitted [][]int
}

type Phase2 struct {
	Parameters struct {
		G1 struct {
			Delta    curve.G1Affine
			Z        []curve.G1Affine   // Z[i] = xⁱt(x)/δ where t is the domain vanishing polynomial 0 ≤ i ≤ N-2
			PKK      []curve.G1Affine   // PKK are the coefficients of the private witness, needed for the proving key. They have a denominator of δ
			SigmaCKK [][]curve.G1Affine // Commitment proof bases: SigmaCKK[i][j] = σᵢCᵢⱼ where Cᵢⱼ is the commitment basis for the jᵗʰ committed element from the iᵗʰ commitment
		}
		G2 struct {
			Delta curve.G2Affine
			Sigma []curve.G2Affine // the secret σ value for each commitment
		}
	}

	// Proofs of update correctness
	Sigmas []mpcsetup.UpdateProof
	Delta  mpcsetup.UpdateProof

	// Challenge is the hash of the PREVIOUS contribution
	Challenge []byte
}

const (
	DST_DELTA = iota
	DST_SIGMA
)

func (p *Phase2) Verify(next *Phase2, options ...verificationOption) error {
	challenge := p.hash()
	if len(next.Challenge) != 0 && !bytes.Equal(next.Challenge, challenge) {
		return errors.New("the challenge does not match the previous contribution's hash")
	}
	next.Challenge = challenge

	if len(next.Parameters.G1.Z) != len(p.Parameters.G1.Z) ||
		len(next.Parameters.G1.PKK) != len(p.Parameters.G1.PKK) ||
		len(next.Parameters.G1.SigmaCKK) != len(p.Parameters.G1.SigmaCKK) ||
		len(next.Parameters.G2.Sigma) != len(p.Parameters.G2.Sigma) {
		return errors.New("contribution size mismatch")
	}

	// check subgroup membership
	var settings verificationSettings
	for _, opt := range options {
		opt(&settings)
	}
	wp := settings.wp
	if wp == nil {
		wp = gcUtils.NewWorkerPool()
		defer wp.Stop()
	}

	subGroupCheckErrors := make(chan error, 2+len(p.Sigmas))
	subGroupErrorReporterNoOffset := func(format string) func(int) {
		return func(i int) {
			subGroupCheckErrors <- fmt.Errorf(format+" representation not in subgroup", i)
		}
	}

	wg := make([]*sync.WaitGroup, 2+len(p.Sigmas))
	wg[0] = areInSubGroupG1(wp, next.Parameters.G1.Z, subGroupErrorReporterNoOffset("[Z[%d]]₁"))
	wg[1] = areInSubGroupG1(wp, next.Parameters.G1.PKK, subGroupErrorReporterNoOffset("[PKK[%d]]₁"))
	for i := range p.Sigmas {
		wg[2+i] = areInSubGroupG1(wp, next.Parameters.G1.SigmaCKK[i], subGroupErrorReporterNoOffset("[σCKK[%d]]₁ (commitment proving key)"))
	}
	for _, wg := range wg {
		wg.Wait()
	}
	close(subGroupCheckErrors)
	for err := range subGroupCheckErrors {
		if err != nil {
			return err
		}
	}

	// verify proof of knowledge of contributions to the σᵢ
	// and the correctness of updates to Parameters.G2.Sigma[i] and the Parameters.G1.SigmaCKK[i]
	for i := range p.Sigmas { // match the first commitment basis elem against the contribution commitment
		if err := next.Sigmas[i].Verify(challenge, DST_SIGMA+byte(i),
			mpcsetup.ValueUpdate{Previous: p.Parameters.G1.SigmaCKK[i], Next: next.Parameters.G1.SigmaCKK[i]},
			mpcsetup.ValueUpdate{Previous: &p.Parameters.G2.Sigma[i], Next: &next.Parameters.G2.Sigma[i]}); err != nil {
			return fmt.Errorf("failed to verify contribution to σ[%d]: %w", i, err)
		}
	}

	// verify proof of knowledge of contribution to δ
	// and the correctness of updates to Parameters.Gi.Delta, PKK[i], and Z[i]
	if err := next.Delta.Verify(challenge, DST_DELTA, []mpcsetup.ValueUpdate{
		{Previous: &p.Parameters.G1.Delta, Next: &next.Parameters.G1.Delta},
		{Previous: &p.Parameters.G2.Delta, Next: &next.Parameters.G2.Delta},
		{Previous: next.Parameters.G1.Z, Next: p.Parameters.G1.Z}, // since these have δ in their denominator, we will do it "backwards"
		{Previous: next.Parameters.G1.PKK, Next: p.Parameters.G1.PKK},
	}...); err != nil {
		return fmt.Errorf("failed to verify contribution to δ: %w", err)
	}

	return nil
}

// update modifies delta
func (p *Phase2) update(delta *fr.Element, sigma []fr.Element) {
	var I big.Int

	scaleG1Slice := func(s []curve.G1Affine) {
		utils.Parallelize(len(s), func(start, end int) {
			for i := start; i < end; i++ {
				s[i].ScalarMultiplication(&s[i], &I)
			}
		})
	}

	for i := range sigma {
		sigma[i].BigInt(&I)
		p.Parameters.G2.Sigma[i].ScalarMultiplication(&p.Parameters.G2.Sigma[i], &I)
		scaleG1Slice(p.Parameters.G1.SigmaCKK[i])
	}

	delta.BigInt(&I)
	p.Parameters.G2.Delta.ScalarMultiplication(&p.Parameters.G2.Delta, &I)
	p.Parameters.G1.Delta.ScalarMultiplication(&p.Parameters.G1.Delta, &I)

	delta.Inverse(delta)
	delta.BigInt(&I)
	scaleG1Slice(p.Parameters.G1.Z)
	scaleG1Slice(p.Parameters.G1.PKK)
}

func (p *Phase2) Contribute() {
	p.Challenge = p.hash()

	// sample value contributions and provide correctness proofs
	var delta fr.Element
	p.Delta = mpcsetup.UpdateValues(&delta, p.Challenge, DST_DELTA)

	sigma := make([]fr.Element, len(p.Parameters.G1.SigmaCKK))
	if len(sigma) > 255 {
		panic("too many commitments") // DST collision
	}
	for i := range sigma {
		p.Sigmas[i] = mpcsetup.UpdateValues(&sigma[i], p.Challenge, DST_SIGMA+byte(i))
	}

	p.update(&delta, sigma)
}

// Initialize is to be run by the coordinator
// It involves no coin tosses. A verifier should
// simply rerun all the steps
func (p *Phase2) Initialize(r1cs *cs.R1CS, commons *SrsCommons) Phase2Evaluations {
	// TODO @Tabaie option to only compute the phase 2 info and not the evaluations, for a contributor

	n := len(commons.G1.AlphaTau)
	if n < r1cs.GetNbConstraints() {
		panic("Number of constraints is larger than expected")
	}

	accumulateG1 := func(res *curve.G1Affine, t constraint.Term, value *curve.G1Affine) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			res.Add(res, value).Add(res, value)
		default:
			var tmp curve.G1Affine
			var vBi big.Int
			r1cs.Coefficients[cID].BigInt(&vBi)
			tmp.ScalarMultiplication(value, &vBi)
			res.Add(res, &tmp)
		}
	}

	accumulateG2 := func(res *curve.G2Affine, t constraint.Term, value *curve.G2Affine) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			res.Add(res, value).Add(res, value)
		default:
			var tmp curve.G2Affine
			var vBi big.Int
			r1cs.Coefficients[cID].BigInt(&vBi)
			tmp.ScalarMultiplication(value, &vBi)
			res.Add(res, &tmp)
		}
	}

	// Prepare Lagrange coefficients of [τ...]₁, [τ...]₂, [ατ...]₁, [βτ...]₁
	coeffTau1 := lagrangeCoeffsG1(commons.G1.Tau, n)           // [L_{ω⁰}(τ)]₁, [L_{ω¹}(τ)]₁, ... where ω is a primitive sizeᵗʰ root of unity
	coeffTau2 := lagrangeCoeffsG2(commons.G2.Tau, n)           // [L_{ω⁰}(τ)]₂, [L_{ω¹}(τ)]₂, ...
	coeffAlphaTau1 := lagrangeCoeffsG1(commons.G1.AlphaTau, n) // [L_{ω⁰}(ατ)]₁, [L_{ω¹}(ατ)]₁, ...
	coeffBetaTau1 := lagrangeCoeffsG1(commons.G1.BetaTau, n)   // [L_{ω⁰}(βτ)]₁, [L_{ω¹}(βτ)]₁, ...

	nbInternal, nbSecret, nbPublic := r1cs.GetNbVariables()
	nWires := nbInternal + nbSecret + nbPublic
	var evals Phase2Evaluations
	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	evals.PublicAndCommitmentCommitted = commitmentInfo.GetPublicAndCommitmentCommitted(commitmentInfo.CommitmentIndexes(), nbPublic)
	evals.G1.A = make([]curve.G1Affine, nWires) // recall: A are the left coefficients in DIZK parlance
	evals.G1.B = make([]curve.G1Affine, nWires) // recall: B are the right coefficients in DIZK parlance
	evals.G2.B = make([]curve.G2Affine, nWires) // recall: A only appears in 𝔾₁ elements in the proof, but B needs to appear in a 𝔾₂ element so the verifier can compute something resembling (A.x).(B.x) via pairings
	bA := make([]curve.G1Affine, nWires)
	aB := make([]curve.G1Affine, nWires)
	C := make([]curve.G1Affine, nWires)

	i := 0
	it := r1cs.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		// each constraint is sparse, i.e. involves a small portion of all variables.
		// so we iterate over the variables involved and add the constraint's contribution
		// to every variable's A, B, and C values

		// A
		for _, t := range c.L {
			accumulateG1(&evals.G1.A[t.WireID()], t, &coeffTau1[i])
			accumulateG1(&bA[t.WireID()], t, &coeffBetaTau1[i])
		}
		// B
		for _, t := range c.R {
			accumulateG1(&evals.G1.B[t.WireID()], t, &coeffTau1[i])
			accumulateG2(&evals.G2.B[t.WireID()], t, &coeffTau2[i])
			accumulateG1(&aB[t.WireID()], t, &coeffAlphaTau1[i])
		}
		// C
		for _, t := range c.O {
			accumulateG1(&C[t.WireID()], t, &coeffTau1[i])
		}
		i++
	}

	// Prepare default contribution
	_, _, g1, g2 := curve.Generators()
	p.Parameters.G1.Delta = g1
	p.Parameters.G2.Delta = g2

	// Build Z in PK as τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	// τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	p.Parameters.G1.Z = make([]curve.G1Affine, n)
	for i := range n - 1 {
		p.Parameters.G1.Z[i].Sub(&commons.G1.Tau[i+n], &commons.G1.Tau[i])
	}
	bitReverse(p.Parameters.G1.Z)
	p.Parameters.G1.Z = p.Parameters.G1.Z[:n-1]

	commitments := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	evals.G1.CKK = make([][]curve.G1Affine, len(commitments))
	p.Sigmas = make([]mpcsetup.UpdateProof, len(commitments))
	p.Parameters.G1.SigmaCKK = make([][]curve.G1Affine, len(commitments))
	p.Parameters.G2.Sigma = make([]curve.G2Affine, len(commitments))

	for j := range commitments {
		evals.G1.CKK[j] = make([]curve.G1Affine, 0, len(commitments[j].PrivateCommitted))
		p.Parameters.G2.Sigma[j] = g2
	}

	nbCommitted := internal.NbElements(commitments.GetPrivateCommitted())

	// Evaluate PKK

	p.Parameters.G1.PKK = make([]curve.G1Affine, 0, nbInternal+nbSecret-nbCommitted-len(commitments))
	evals.G1.VKK = make([]curve.G1Affine, 0, nbPublic+len(commitments))
	committedIterator := internal.NewMergeIterator(commitments.GetPrivateCommitted())
	nbCommitmentsSeen := 0
	for j := 0; j < nWires; j++ {
		// since as yet δ, γ = 1, the VKK and PKK are computed identically, as βA + αB + C
		var tmp curve.G1Affine
		tmp.Add(&bA[j], &aB[j])
		tmp.Add(&tmp, &C[j])
		commitmentIndex := committedIterator.IndexIfNext(j)
		isCommitment := nbCommitmentsSeen < len(commitments) && commitments[nbCommitmentsSeen].CommitmentIndex == j
		if commitmentIndex != -1 {
			evals.G1.CKK[commitmentIndex] = append(evals.G1.CKK[commitmentIndex], tmp)
		} else if j < nbPublic || isCommitment {
			evals.G1.VKK = append(evals.G1.VKK, tmp)
		} else {
			p.Parameters.G1.PKK = append(p.Parameters.G1.PKK, tmp)
		}
		if isCommitment {
			nbCommitmentsSeen++
		}
	}

	for j := range commitments {
		p.Parameters.G1.SigmaCKK[j] = slices.Clone(evals.G1.CKK[j])
	}

	p.Challenge = nil

	return evals
}

// VerifyPhase2 for circuit described by r1cs
// using parameters from commons
// beaconChallenge is a random beacon of moderate entropy evaluated at a time later than the latest contribution.
// It seeds a final "contribution" to the protocol, reproducible by any verifier.
// For more information on random beacons, refer to https://a16zcrypto.com/posts/article/public-randomness-and-randomness-beacons/
// Organizations such as the League of Entropy (https://leagueofentropy.com/) provide such beacons. THIS IS NOT A RECOMMENDATION OR ENDORSEMENT.
// and c are the output from the contributors
// WARNING: the last contribution object will be modified
func VerifyPhase2(r1cs *cs.R1CS, commons *SrsCommons, beaconChallenge []byte, c ...*Phase2) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	prev := new(Phase2)
	evals := prev.Initialize(r1cs, commons)
	wp := gcUtils.NewWorkerPool()
	defer wp.Stop()
	for i := range c {
		if err := prev.Verify(c[i], WithWorkerPool(wp)); err != nil {
			return nil, nil, err
		}
		prev = c[i]
	}

	pk, vk := prev.Seal(commons, &evals, beaconChallenge)
	return pk, vk, nil
}

func (p *Phase2) hash() []byte {
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	return sha.Sum(nil)
}
