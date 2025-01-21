// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/mpcsetup"
	"math/big"
)

// SrsCommons are the circuit-independent components of the Groth16 SRS,
// computed by the first phase.
// in all that follows, N is the domain size
type SrsCommons struct {
	G1 struct {
		Tau      []curve.G1Affine // {[τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ᴺ⁻²]₁}
		AlphaTau []curve.G1Affine // {α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τᴺ⁻¹]₁}
		BetaTau  []curve.G1Affine // {β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τᴺ⁻¹]₁}
	}
	G2 struct {
		Tau  []curve.G2Affine // {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τᴺ⁻¹]₂}
		Beta curve.G2Affine   // [β]₂
	}
}

// Phase1 in line with Phase1 of the MPC described in
// https://eprint.iacr.org/2017/1050.pdf
//
// Also known as "Powers of Tau"
type Phase1 struct {
	proofs struct {
		Tau, Alpha, Beta mpcsetup.UpdateProof
	}
	parameters SrsCommons
	Challenge  []byte // Hash of the transcript PRIOR to this participant
}

// Contribute contributes randomness to the Phase1 object. This mutates Phase1.
// p is trusted to be well-formed. The ReadFrom function performs such basic sanity checks.
func (p *Phase1) Contribute() {
	p.Challenge = p.hash()

	// Generate main value updates
	var (
		tauContrib, alphaContrib, betaContrib fr.Element
	)

	p.proofs.Tau = mpcsetup.UpdateValues(&tauContrib, p.Challenge, 1)
	p.proofs.Alpha = mpcsetup.UpdateValues(&alphaContrib, p.Challenge, 2)
	p.proofs.Beta = mpcsetup.UpdateValues(&betaContrib, p.Challenge, 3)

	p.parameters.update(&tauContrib, &alphaContrib, &betaContrib)
}

// setZero instantiates the parameters, and sets all contributions to zero
func (c *SrsCommons) setZero(N uint64) {
	c.G1.Tau = make([]curve.G1Affine, 2*N-1)
	c.G2.Tau = make([]curve.G2Affine, N)
	c.G1.AlphaTau = make([]curve.G1Affine, N)
	c.G1.BetaTau = make([]curve.G1Affine, N)
	_, _, c.G1.Tau[0], c.G2.Tau[0] = curve.Generators()
}

// setOne instantiates the parameters, and sets all contributions to one
func (c *SrsCommons) setOne(N uint64) {
	c.setZero(N)
	g1, g2 := &c.G1.Tau[0], &c.G2.Tau[0]
	setG1 := func(s []curve.G1Affine) {
		for i := range s {
			s[i].Set(g1)
		}
	}
	setG2 := func(s []curve.G2Affine) {
		for i := range s {
			s[i].Set(g2)
		}
	}

	setG1(c.G1.Tau[1:])
	setG2(c.G2.Tau[1:])
	setG1(c.G1.AlphaTau)
	setG1(c.G1.BetaTau)
	c.G2.Beta.Set(g2)
}

// from the fourth argument on this just gives an opportunity to avoid recomputing some scalar multiplications
func (c *SrsCommons) update(tauUpdate, alphaUpdate, betaUpdate *fr.Element) {

	// TODO @gbotrel working with jacobian points here will help with perf.

	tauUpdates := powers(tauUpdate, len(c.G1.Tau))

	scaleG1InPlace(c.G1.Tau[1:], tauUpdates[1:]) // first element remains 1
	scaleG2InPlace(c.G2.Tau[1:], tauUpdates[1:])

	alphaUpdates := make([]fr.Element, len(c.G1.AlphaTau))
	alphaUpdates[0].Set(alphaUpdate)
	for i := range alphaUpdates {
		// let α₁ = α₀.α', τ₁ = τ₀.τ'
		// then α₁τ₁ⁱ = (α₀τ₀ⁱ)α'τ'ⁱ
		alphaUpdates[i].Mul(&tauUpdates[i], alphaUpdate)
	}
	scaleG1InPlace(c.G1.AlphaTau, alphaUpdates)

	betaUpdates := make([]fr.Element, len(c.G1.BetaTau))
	betaUpdates[0].Set(betaUpdate)
	for i := range betaUpdates {
		betaUpdates[i].Mul(&tauUpdates[i], betaUpdate)
	}
	scaleG1InPlace(c.G1.BetaTau, betaUpdates)

	var betaUpdateI big.Int
	betaUpdate.BigInt(&betaUpdateI)
	c.G2.Beta.ScalarMultiplication(&c.G2.Beta, &betaUpdateI)
}

// Seal performs the final contribution and outputs the final parameters.
// No randomization is performed at this step.
// A verifier should simply re-run this and check
// that it produces the same values.
// The inner workings of the random beacon are out of scope.
// WARNING: Seal modifies p, just as Contribute does.
// The result will be an INVALID Phase1 object, since no proof of correctness is produced.
func (p *Phase1) Seal(beaconChallenge []byte) SrsCommons {
	newContribs := mpcsetup.BeaconContributions(p.hash(), []byte("Groth16 MPC Setup - Phase 1"), beaconChallenge, 3)
	p.parameters.update(&newContribs[0], &newContribs[1], &newContribs[2])
	return p.parameters
}

// VerifyPhase1 and return the SRS parameters usable for any circuit of domain size N
// beaconChallenge is the output of the random beacon
// and c are the output from the contributors
// WARNING: the last contribution object will be modified
func VerifyPhase1(N uint64, beaconChallenge []byte, c ...*Phase1) (SrsCommons, error) {
	prev := NewPhase1(N)
	for i := range c {
		if err := prev.Verify(c[i]); err != nil {
			return SrsCommons{}, err
		}
		prev = c[i]
	}
	return prev.Seal(beaconChallenge), nil
}

// Verify assumes previous is correct
func (p *Phase1) Verify(next *Phase1) error {

	challenge := p.hash()
	if len(next.Challenge) != 0 && !bytes.Equal(next.Challenge, challenge) {
		return errors.New("the challenge does not match the previous contribution's hash")
	}
	next.Challenge = challenge

	// the internal consistency of the vector sizes in next is assumed
	// so is its well-formedness i.e. Tau[0] = 1
	// it remains to check it is consistent with p
	N := len(next.parameters.G2.Tau)
	if N != len(p.parameters.G2.Tau) {
		return errors.New("domain size mismatch")
	}

	// verify updates to τ, α, β
	if err := next.proofs.Tau.Verify(challenge, 1, mpcsetup.ValueUpdate{Previous: &p.parameters.G1.Tau[1], Next: &next.parameters.G1.Tau[1]}); err != nil {
		return fmt.Errorf("failed to verify contribution to τ: %w", err)
	}
	if err := next.proofs.Alpha.Verify(challenge, 2, mpcsetup.ValueUpdate{Previous: p.parameters.G1.AlphaTau[0], Next: next.parameters.G1.AlphaTau[0]}); err != nil {
		return fmt.Errorf("failed to verify contribution to α: %w", err)
	}
	if err := next.proofs.Beta.Verify(challenge, 3, []mpcsetup.ValueUpdate{
		{Previous: &p.parameters.G1.BetaTau[0], Next: &next.parameters.G1.BetaTau[0]},
		{Previous: &p.parameters.G2.Beta, Next: &next.parameters.G2.Beta},
	}...); err != nil {
		return fmt.Errorf("failed to verify contribution to β: %w", err)
	}

	if !areInSubGroupG1(next.parameters.G1.Tau[2:]) || !areInSubGroupG1(next.parameters.G1.BetaTau[1:]) || !areInSubGroupG1(next.parameters.G1.AlphaTau[1:]) {
		return errors.New("derived values 𝔾₁ subgroup check failed")
	}
	if !areInSubGroupG2(next.parameters.G2.Tau[2:]) {
		return errors.New("derived values 𝔾₂ subgroup check failed")
	}

	return mpcsetup.SameRatioMany(
		p.parameters.G1.Tau,
		p.parameters.G2.Tau,
		p.parameters.G1.AlphaTau,
		p.parameters.G1.BetaTau,
	)
}

func (p *Phase1) hash() []byte {
	sha := sha256.New()
	if _, err := p.WriteTo(sha); err != nil {
		panic(err)
	}
	sha.Write(p.Challenge)
	return sha.Sum(nil)
}

// Initialize an empty Phase1 contribution object
// to be used by the first contributor or the verifier
// N is the FFT domain size
func (p *Phase1) Initialize(N uint64) {
	if ecc.NextPowerOfTwo(N) != N {
		panic("N must be a power of 2")
	}
	p.parameters.setOne(N)
}

// NewPhase1 creates an empty Phase1 contribution object
// to be used by the first contributor or the verifier
// N is the FFT domain size
func NewPhase1(N uint64) *Phase1 {
	res := new(Phase1)
	res.Initialize(N)
	return res
}
