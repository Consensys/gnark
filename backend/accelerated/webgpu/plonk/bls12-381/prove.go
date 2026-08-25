//go:build js && wasm

// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package bls12381

import (
	"errors"
	"fmt"
	"hash"
	"math/big"
	"math/bits"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/accelerated/webgpu/plonk/internal/bridge"
	native "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
)

const (
	id_L int = iota
	id_R
	id_O
	id_Z
	id_ZS
	id_Ql
	id_Qr
	id_Qm
	id_Qo
	id_Qk
	id_S1
	id_S2
	id_S3
	id_Qci // [ .. , Qc_i, Pi_i, ...]
)

// blinding factors
const (
	id_Bl int = iota
	id_Br
	id_Bo
	id_Bz
	nb_blinding_polynomials
)

// blinding orders (-1 to deactivate)
const (
	order_blinding_L = 1
	order_blinding_R = 1
	order_blinding_O = 1
	order_blinding_Z = 2
)

func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (proof *native.Proof, err error) {
	// parse the options
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("get prover options: %w", err)
	}

	if err := pk.Prepare(); err != nil {
		return nil, fmt.Errorf("prepare proving key: %w", err)
	}

	// init instance
	instance, err := newInstance(spr, pk, fullWitness, &opt)
	if err != nil {
		return nil, fmt.Errorf("new instance: %w", err)
	}

	if err := instance.initBlindingPolynomials(); err != nil {
		return nil, fmt.Errorf("init blinding polynomials: %w", err)
	}
	if err := instance.solveConstraints(); err != nil {
		return nil, fmt.Errorf("solve constraints: %w", err)
	}
	if err := instance.completeQk(); err != nil {
		return nil, fmt.Errorf("complete qk: %w", err)
	}
	if err := instance.deriveGammaAndBeta(); err != nil {
		return nil, fmt.Errorf("derive gamma and beta: %w", err)
	}
	if err := instance.buildRatioCopyConstraint(); err != nil {
		return nil, fmt.Errorf("build ratio copy constraint: %w", err)
	}
	if err := instance.computeQuotient(); err != nil {
		return nil, fmt.Errorf("compute quotient: %w", err)
	}
	if err := instance.openZ(); err != nil {
		return nil, fmt.Errorf("open z: %w", err)
	}
	if err := instance.computeLinearizedPolynomial(); err != nil {
		return nil, fmt.Errorf("compute linearized polynomial: %w", err)
	}
	if err := instance.batchOpening(); err != nil {
		return nil, fmt.Errorf("batch opening: %w", err)
	}

	return instance.proof, nil
}

// represents a Prover instance
type instance struct {
	pk    *ProvingKey
	proof *native.Proof
	spr   *cs.SparseR1CS
	opt   *backend.ProverConfig

	fs             *fiatshamir.Transcript
	kzgFoldingHash hash.Hash // for KZG folding
	htfFunc        hash.Hash // hash to field function

	// polynomials
	x                         []*iop.Polynomial // x stores tracks the polynomial we need
	bp                        []*iop.Polynomial // blinding polynomials
	h                         *iop.Polynomial   // h is the quotient polynomial
	blindedZ                  []fr.Element      // blindedZ is the blinded version of Z
	quotientShardsRandomizers [2]fr.Element     // random elements for blinding the shards of the quotient

	precomputedDenominators    []fr.Element // stores the denominators of the Lagrange polynomials
	linearizedPolynomial       []fr.Element
	linearizedPolynomialDigest kzg.Digest

	fullWitness witness.Witness

	// bsb22 commitment stuff
	commitmentInfo constraint.PlonkCommitments
	commitmentVal  []fr.Element
	cCommitments   []*iop.Polynomial

	// challenges
	gamma, beta, alpha, zeta fr.Element

	domain0, domain1 *fft.Domain

	trace *native.Trace
}

func newInstance(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts *backend.ProverConfig) (*instance, error) {
	if opts.HashToFieldFn == nil {
		opts.HashToFieldFn = hash_to_field.New([]byte("BSB22-Plonk"))
	}
	s := instance{
		pk:             pk,
		proof:          &native.Proof{},
		spr:            spr,
		opt:            opts,
		fullWitness:    fullWitness,
		bp:             make([]*iop.Polynomial, nb_blinding_polynomials),
		fs:             fiatshamir.NewTranscript(opts.ChallengeHash, "gamma", "beta", "alpha", "zeta"),
		kzgFoldingHash: opts.KZGFoldingHash,
		htfFunc:        opts.HashToFieldFn,
	}
	s.initBSB22Commitments()
	s.x = make([]*iop.Polynomial, id_Qci+2*len(s.commitmentInfo))

	// init fft domains
	s.domain0, s.domain1 = domainsForSPR(spr)

	// sampling random numbers for blinding the quotient
	if opts.StatisticalZK {
		s.quotientShardsRandomizers[0].SetRandom()
		s.quotientShardsRandomizers[1].SetRandom()
	}

	// build trace
	s.trace = native.NewTrace(spr, s.domain0)
	if err := pk.ensureStaticNumeratorCacheForTrace(s.trace, s.domain0, s.domain1); err != nil {
		return nil, err
	}

	return &s, nil
}

func domainsForSPR(spr *cs.SparseR1CS) (*fft.Domain, *fft.Domain) {
	nbConstraints := spr.GetNbConstraints()
	sizeSystem := uint64(nbConstraints + len(spr.Public)) // len(spr.Public) is for the placeholder constraints
	domain0 := fft.NewDomain(sizeSystem)

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	var domain1 *fft.Domain
	if sizeSystem < 6 {
		domain1 = fft.NewDomain(8*sizeSystem, fft.WithoutPrecompute())
	} else {
		domain1 = fft.NewDomain(4*sizeSystem, fft.WithoutPrecompute())
	}
	return domain0, domain1
}

func (s *instance) initBlindingPolynomials() error {
	s.bp[id_Bl] = getRandomPolynomial(order_blinding_L)
	s.bp[id_Br] = getRandomPolynomial(order_blinding_R)
	s.bp[id_Bo] = getRandomPolynomial(order_blinding_O)
	s.bp[id_Bz] = getRandomPolynomial(order_blinding_Z)
	return nil
}

func (s *instance) initBSB22Commitments() {
	s.commitmentInfo = s.spr.CommitmentInfo.(constraint.PlonkCommitments)
	s.commitmentVal = make([]fr.Element, len(s.commitmentInfo)) // TODO @Tabaie get rid of this
	s.cCommitments = make([]*iop.Polynomial, len(s.commitmentInfo))
	s.proof.Bsb22Commitments = make([]kzg.Digest, len(s.commitmentInfo))

	// override the hint for the commitment constraints
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	s.opt.SolverOpts = append(s.opt.SolverOpts, solver.OverrideHint(bsb22ID, s.bsb22Hint))
}

// Computing and verifying Bsb22 multi-commits explained in https://hackmd.io/x8KsadW3RRyX7YTCFJIkHg
func (s *instance) bsb22Hint(_ *big.Int, ins, outs []*big.Int) error {
	var err error
	commDepth := int(ins[0].Int64())
	ins = ins[1:]

	res := &s.commitmentVal[commDepth]

	commitmentInfo := s.spr.CommitmentInfo.(constraint.PlonkCommitments)[commDepth]
	committedValues := make([]fr.Element, s.domain0.Cardinality)
	offset := s.spr.GetNbPublicVariables()
	for i := range ins {
		committedValues[offset+commitmentInfo.Committed[i]].SetBigInt(ins[i])
	}
	if _, err = committedValues[offset+commitmentInfo.CommitmentIndex].SetRandom(); err != nil { // Commitment injection constraint has qcp = 0. Safe to use for blinding.
		return err
	}
	if _, err = committedValues[offset+s.spr.GetNbConstraints()-1].SetRandom(); err != nil { // Last constraint has qcp = 0. Safe to use for blinding
		return err
	}
	s.cCommitments[commDepth] = iop.NewPolynomial(&committedValues, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	if s.proof.Bsb22Commitments[commDepth], err = kzg.Commit(s.cCommitments[commDepth].Coefficients(), s.pk.KzgLagrange, 1); err != nil {
		return err
	}

	s.htfFunc.Write(s.proof.Bsb22Commitments[commDepth].Marshal())
	hashBts := s.htfFunc.Sum(nil)
	s.htfFunc.Reset()
	nbBuf := fr.Bytes
	if s.htfFunc.Size() < fr.Bytes {
		nbBuf = s.htfFunc.Size()
	}
	res.SetBytes(hashBts[:nbBuf]) // TODO @Tabaie use CommitmentIndex for this; create a new variable CommitmentConstraintIndex for other uses
	res.BigInt(outs[0])

	return nil
}

// solveConstraints computes the evaluation of the polynomials L, R, O
// and sets x[id_L], x[id_R], x[id_O] in Lagrange form
func (s *instance) solveConstraints() error {
	_solution, err := s.spr.Solve(s.fullWitness, s.opt.SolverOpts...)
	if err != nil {
		return err
	}
	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	s.x[id_L] = iop.NewPolynomial(&evaluationLDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	s.x[id_R] = iop.NewPolynomial(&evaluationRDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	s.x[id_O] = iop.NewPolynomial(&evaluationODomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})

	// commit to l, r, o and add blinding factors
	if err := s.commitToLRO(); err != nil {
		return err
	}
	return nil
}

func (s *instance) completeQk() error {
	qk := s.trace.Qk.Clone()
	qkCoeffs := qk.Coefficients()

	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	copy(qkCoeffs, wWitness[:len(s.spr.Public)])

	for i := range s.commitmentInfo {
		qkCoeffs[s.spr.GetNbPublicVariables()+s.commitmentInfo[i].CommitmentIndex] = s.commitmentVal[i]
	}

	s.x[id_Qk] = qk

	return nil
}

// commitToLRO commits to L, R, O polynomials using reduced-size MSMs.
//
// L, R, O live on a domain of size n = 2^k, but only offset = nbPublic + nbConstraints
// entries carry actual values. The rest are s0 = witness[0] (first public input).
// For R and O, the first nbPublic entries (placeholders) are also s0.
//
// Key identity: Σ_{i=0}^{n-1} KzgLagrange.G1[i] = [Σ L_i(τ)]₁ = [1]₁ = Kzg.G1[0]
//
// So we can rewrite the commitment as:
//
//	[P] = Σ P[i]·G1_lag[i]
//	    = Σ (P[i]-s0)·G1_lag[i] + s0·Σ G1_lag[i]
//	    = MSM((P[i]-s0), G1_lag[i])  + s0·Kzg.G1[0]
//
// The (P[i]-s0) terms are zero in the padding region, so the MSM only needs
// the non-padding entries. For a 2.2M-constraint circuit on a 4M domain,
// this nearly halves each MSM.
func (s *instance) commitToLRO() error {
	n := int(s.domain0.Cardinality)
	nbPublic := len(s.spr.Public)
	offset := nbPublic + s.spr.GetNbConstraints()

	// s0 = witness[0] = first public input
	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}
	s0 := wWitness[0]

	// correctionPoint = s0 · [1]₁ = s0 · Kzg.G1[0]
	var s0BigInt big.Int
	s0.BigInt(&s0BigInt)
	var correctionPoint curve.G1Affine
	correctionPoint.ScalarMultiplication(&s.pk.Kzg.G1[0], &s0BigInt)

	// L: subtract s0, MSM on [0:offset], add correction + blinding, restore
	coeffs := s.x[id_L].Coefficients()
	for i := 0; i < offset; i++ {
		coeffs[i].Sub(&coeffs[i], &s0)
	}
	var commit curve.G1Affine
	commit, err := s.msmG1("kzgLagrange", 0, coeffs[:offset])
	if err != nil {
		return err
	}
	for i := 0; i < offset; i++ {
		coeffs[i].Add(&coeffs[i], &s0)
	}
	commit.Add(&commit, &correctionPoint)
	cb := commitBlindingFactor(n, s.bp[id_Bl], s.pk.Kzg)
	s.proof.LRO[0].Add(&commit, &cb)

	// R: subtract s0, MSM on [nbPublic:offset], add correction + blinding, restore
	coeffs = s.x[id_R].Coefficients()
	for i := nbPublic; i < offset; i++ {
		coeffs[i].Sub(&coeffs[i], &s0)
	}
	commit, err = s.msmG1("kzgLagrange", nbPublic, coeffs[nbPublic:offset])
	if err != nil {
		return err
	}
	for i := nbPublic; i < offset; i++ {
		coeffs[i].Add(&coeffs[i], &s0)
	}
	commit.Add(&commit, &correctionPoint)
	cb = commitBlindingFactor(n, s.bp[id_Br], s.pk.Kzg)
	s.proof.LRO[1].Add(&commit, &cb)

	// O: same as R
	coeffs = s.x[id_O].Coefficients()
	for i := nbPublic; i < offset; i++ {
		coeffs[i].Sub(&coeffs[i], &s0)
	}
	commit, err = s.msmG1("kzgLagrange", nbPublic, coeffs[nbPublic:offset])
	if err != nil {
		return err
	}
	for i := nbPublic; i < offset; i++ {
		coeffs[i].Add(&coeffs[i], &s0)
	}
	commit.Add(&commit, &correctionPoint)
	cb = commitBlindingFactor(n, s.bp[id_Bo], s.pk.Kzg)
	s.proof.LRO[2].Add(&commit, &cb)

	return nil
}

func (s *instance) msmG1(vectorName string, start int, scalars []fr.Element) (curve.G1Affine, error) {
	scalarsPacked := packFrVectorRegularLEInto(nil, scalars)
	packed, err := bridge.Bridge.MSMG1Slice(s.pk.handle, vectorName, start, len(scalars), scalarsPacked)
	return decodeG1AffineFromPacked(packed, err)
}

func (s *instance) msmG1Batch(vectorName string, start int, scalarVectors ...[]fr.Element) ([]curve.G1Affine, error) {
	if len(scalarVectors) == 0 {
		return nil, errors.New("webgpu plonk bls12_381: empty MSM batch")
	}
	termCount := 0
	for _, scalars := range scalarVectors {
		if len(scalars) > termCount {
			termCount = len(scalars)
		}
	}
	scalarsPacked, err := packFrVectorsRegularLEPaddedInto(nil, scalarVectors, termCount)
	if err != nil {
		return nil, err
	}
	packed, err := bridge.Bridge.MSMG1Batch(s.pk.handle, vectorName, start, termCount, len(scalarVectors), scalarsPacked)
	return decodeG1AffineBatchFromPacked(packed, len(scalarVectors), err)
}

// deriveGammaAndBeta (copy constraint)
func (s *instance) deriveGammaAndBeta() error {
	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	if err := bindPublicData(s.fs, "gamma", s.pk.Vk, wWitness[:len(s.spr.Public)]); err != nil {
		return err
	}

	gamma, err := deriveRandomness(s.fs, "gamma", &s.proof.LRO[0], &s.proof.LRO[1], &s.proof.LRO[2])
	if err != nil {
		return err
	}

	bbeta, err := s.fs.ComputeChallenge("beta")
	if err != nil {
		return err
	}
	s.gamma = gamma
	s.beta.SetBytes(bbeta)

	return nil
}

// commitToPolyAndBlinding computes the KZG commitment of a polynomial p
// in Lagrange form (large degree)
// and add the contribution of a blinding polynomial b (small degree)
// /!\ The polynomial p is supposed to be in Lagrange form.
func (s *instance) commitToPolyAndBlinding(p, b *iop.Polynomial) (commit curve.G1Affine, err error) {

	commit, err = s.msmG1("kzgLagrange", 0, p.Coefficients())

	// we add in the blinding contribution
	n := int(s.domain0.Cardinality)
	cb := commitBlindingFactor(n, b, s.pk.Kzg)
	commit.Add(&commit, &cb)

	return
}

func (s *instance) deriveAlpha() (err error) {
	alphaDeps := make([]*curve.G1Affine, len(s.proof.Bsb22Commitments)+1)
	for i := range s.proof.Bsb22Commitments {
		alphaDeps[i] = &s.proof.Bsb22Commitments[i]
	}
	alphaDeps[len(alphaDeps)-1] = &s.proof.Z
	s.alpha, err = deriveRandomness(s.fs, "alpha", alphaDeps...)
	return err
}

func (s *instance) deriveZeta() (err error) {
	s.zeta, err = deriveRandomness(s.fs, "zeta", &s.proof.H[0], &s.proof.H[1], &s.proof.H[2])
	return
}

// computeQuotient computes H
func (s *instance) computeQuotient() (err error) {
	s.x[id_Ql] = s.trace.Ql
	s.x[id_Qr] = s.trace.Qr
	s.x[id_Qm] = s.trace.Qm
	s.x[id_Qo] = s.trace.Qo
	s.x[id_S1] = s.trace.S1
	s.x[id_S2] = s.trace.S2
	s.x[id_S3] = s.trace.S3

	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i] = s.trace.Qcp[i]
	}

	n := s.domain0.Cardinality
	lone := make([]fr.Element, n)
	lone[0].SetOne()

	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i+1] = s.cCommitments[i]
	}

	// derive alpha
	if err = s.deriveAlpha(); err != nil {
		return err
	}

	// TODO complete waste of memory find another way to do that
	identity := make([]fr.Element, n)
	identity[1].Set(&s.beta)

	s.x[id_ZS] = s.x[id_Z].ShallowClone().Shift(1)

	numerator, err := s.computeNumerator()
	if err != nil {
		return err
	}

	s.h, err = divideByZH(numerator, [2]*fft.Domain{s.domain0, s.domain1})
	if err != nil {
		return err
	}

	// commit to h
	if err := s.commitToQuotient(s.h1(), s.h2(), s.h3()); err != nil {
		return err
	}

	if err := s.deriveZeta(); err != nil {
		return err
	}

	return nil
}

func (s *instance) buildRatioCopyConstraint() (err error) {
	// TODO @gbotrel having iop.BuildRatioCopyConstraint return something
	// with capacity = len() + 4 would avoid extra alloc / copy during openZ
	s.x[id_Z], err = iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{
			s.x[id_L],
			s.x[id_R],
			s.x[id_O],
		},
		s.trace.S,
		s.beta,
		s.gamma,
		iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
		s.domain0,
	)
	if err != nil {
		return err
	}

	// commit to the blinded version of z
	s.proof.Z, err = s.commitToPolyAndBlinding(s.x[id_Z], s.bp[id_Bz])

	return
}

// open Z (blinded) at ωζ
func (s *instance) openZ() (err error) {
	var zetaShifted fr.Element
	zetaShifted.Mul(&s.zeta, &s.pk.Vk.Generator)
	s.blindedZ = getBlindedCoefficients(s.x[id_Z], s.bp[id_Bz])
	// open z at zeta
	s.proof.ZShiftedOpening, err = s.openKZG(s.blindedZ, zetaShifted)
	if err != nil {
		return err
	}
	return nil
}

func (s *instance) openKZG(p []fr.Element, point fr.Element) (kzg.OpeningProof, error) {
	if len(p) > len(s.pk.Kzg.G1) {
		return kzg.OpeningProof{}, kzg.ErrInvalidPolynomialSize
	}

	var proof kzg.OpeningProof
	proof.ClaimedValue = evalKZGPolynomial(p, point)

	cp := make([]fr.Element, len(p))
	copy(cp, p)
	h := dividePolyByXMinusA(cp, proof.ClaimedValue, point)

	hCommit, err := s.msmG1("kzg", 0, h)
	if err != nil {
		return kzg.OpeningProof{}, err
	}
	proof.H.Set(&hCommit)

	return proof, nil
}

func (s *instance) h1() []fr.Element {
	var h1 []fr.Element
	if !s.opt.StatisticalZK {
		h1 = s.h.Coefficients()[:s.domain0.Cardinality+2]
	} else {
		h1 = make([]fr.Element, s.domain0.Cardinality+3)
		copy(h1, s.h.Coefficients()[:s.domain0.Cardinality+2])
		h1[s.domain0.Cardinality+2].Set(&s.quotientShardsRandomizers[0])
	}
	return h1
}

func (s *instance) h2() []fr.Element {
	var h2 []fr.Element
	if !s.opt.StatisticalZK {
		h2 = s.h.Coefficients()[s.domain0.Cardinality+2 : 2*(s.domain0.Cardinality+2)]
	} else {
		h2 = make([]fr.Element, s.domain0.Cardinality+3)
		copy(h2, s.h.Coefficients()[s.domain0.Cardinality+2:2*(s.domain0.Cardinality+2)])
		h2[0].Sub(&h2[0], &s.quotientShardsRandomizers[0])
		h2[s.domain0.Cardinality+2].Set(&s.quotientShardsRandomizers[1])
	}
	return h2
}

func (s *instance) h3() []fr.Element {
	var h3 []fr.Element
	if !s.opt.StatisticalZK {
		h3 = s.h.Coefficients()[2*(s.domain0.Cardinality+2) : 3*(s.domain0.Cardinality+2)]
	} else {
		h3 = make([]fr.Element, s.domain0.Cardinality+2)
		copy(h3, s.h.Coefficients()[2*(s.domain0.Cardinality+2):3*(s.domain0.Cardinality+2)])
		h3[0].Sub(&h3[0], &s.quotientShardsRandomizers[1])
	}
	return h3
}

func (s *instance) computeLinearizedPolynomial() error {
	qcpzeta := make([]fr.Element, len(s.commitmentInfo))
	for i := range s.commitmentInfo {
		qcpzeta[i] = s.trace.Qcp[i].Evaluate(s.zeta)
	}

	blzeta := evaluateBlinded(s.x[id_L], s.bp[id_Bl], s.zeta)
	brzeta := evaluateBlinded(s.x[id_R], s.bp[id_Br], s.zeta)
	bozeta := evaluateBlinded(s.x[id_O], s.bp[id_Bo], s.zeta)
	bzuzeta := s.proof.ZShiftedOpening.ClaimedValue

	linearizedPolynomial, err := s.innerComputeLinearizedPoly(
		blzeta,
		brzeta,
		bozeta,
		s.alpha,
		s.beta,
		s.gamma,
		s.zeta,
		bzuzeta,
		qcpzeta,
		s.blindedZ,
		coefficients(s.cCommitments),
		s.pk,
	)
	if err != nil {
		return err
	}
	s.linearizedPolynomial = linearizedPolynomial

	s.linearizedPolynomialDigest, err = s.msmG1("kzg", 0, s.linearizedPolynomial)
	return err
}

func (s *instance) batchOpening() error {
	polysQcp := coefficients(s.trace.Qcp)
	polysToOpen := make([][]fr.Element, 6+len(polysQcp))
	copy(polysToOpen[6:], polysQcp)

	polysToOpen[0] = s.linearizedPolynomial
	polysToOpen[1] = getBlindedCoefficients(s.x[id_L], s.bp[id_Bl])
	polysToOpen[2] = getBlindedCoefficients(s.x[id_R], s.bp[id_Br])
	polysToOpen[3] = getBlindedCoefficients(s.x[id_O], s.bp[id_Bo])
	polysToOpen[4] = s.trace.S1.Coefficients()
	polysToOpen[5] = s.trace.S2.Coefficients()

	digestsToOpen := make([]curve.G1Affine, len(s.pk.Vk.Qcp)+6)
	copy(digestsToOpen[6:], s.pk.Vk.Qcp)

	digestsToOpen[0] = s.linearizedPolynomialDigest
	digestsToOpen[1] = s.proof.LRO[0]
	digestsToOpen[2] = s.proof.LRO[1]
	digestsToOpen[3] = s.proof.LRO[2]
	digestsToOpen[4] = s.pk.Vk.S[0]
	digestsToOpen[5] = s.pk.Vk.S[1]

	var err error
	s.proof.BatchedProof, err = s.batchOpenSinglePoint(
		polysToOpen,
		digestsToOpen,
		s.zeta,
		s.kzgFoldingHash,
		s.proof.ZShiftedOpening.ClaimedValue.Marshal(),
	)
	return err
}

func (s *instance) batchOpenSinglePoint(polynomials [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, dataTranscript ...[]byte) (kzg.BatchOpeningProof, error) {
	nbDigests := len(digests)
	if nbDigests != len(polynomials) {
		return kzg.BatchOpeningProof{}, kzg.ErrInvalidNbDigests
	}
	if nbDigests == 0 {
		return kzg.BatchOpeningProof{}, kzg.ErrZeroNbDigests
	}

	largestPoly := -1
	for _, p := range polynomials {
		if len(p) > len(s.pk.Kzg.G1) {
			return kzg.BatchOpeningProof{}, kzg.ErrInvalidPolynomialSize
		}
		if len(p) > largestPoly {
			largestPoly = len(p)
		}
	}

	var res kzg.BatchOpeningProof
	res.ClaimedValues = make([]fr.Element, len(polynomials))
	for i := range polynomials {
		res.ClaimedValues[i] = evalKZGPolynomial(polynomials[i], point)
	}

	gamma, err := deriveKZGBatchGamma(point, digests, res.ClaimedValues, hf, dataTranscript...)
	if err != nil {
		return kzg.BatchOpeningProof{}, err
	}

	var foldedEvaluations fr.Element
	foldedEvaluations = res.ClaimedValues[nbDigests-1]
	for i := nbDigests - 2; i >= 0; i-- {
		foldedEvaluations.Mul(&foldedEvaluations, &gamma).
			Add(&foldedEvaluations, &res.ClaimedValues[i])
	}

	foldedPolynomials := make([]fr.Element, largestPoly)
	copy(foldedPolynomials, polynomials[0])

	gammaPower := gamma
	for i := 1; i < len(polynomials); i++ {
		var term fr.Element
		for j := range polynomials[i] {
			term.Mul(&polynomials[i][j], &gammaPower)
			foldedPolynomials[j].Add(&foldedPolynomials[j], &term)
		}
		gammaPower.Mul(&gammaPower, &gamma)
	}

	h := dividePolyByXMinusA(foldedPolynomials, foldedEvaluations, point)

	hCommit, err := s.msmG1("kzg", 0, h)
	if err != nil {
		return kzg.BatchOpeningProof{}, err
	}
	res.H.Set(&hCommit)

	return res, nil
}

// evaluate the full set of constraints, all polynomials in x are back in
// canonical regular form at the end
func (s *instance) computeNumerator() (*iop.Polynomial, error) {
	// init vectors that are used multiple times throughout the computation
	n := s.domain0.Cardinality

	rho := int(s.domain1.Cardinality / n)

	// init the result polynomial & buffer
	cres := make([]fr.Element, s.domain1.Cardinality)
	buf := make([]fr.Element, n)

	// pre-computed to compute the bit reverse index
	// of the result polynomial
	m := uint64(s.domain1.Cardinality)
	mm := uint64(64 - bits.TrailingZeros64(m))

	dynamicPolyIDs := []int{id_L, id_R, id_O, id_Z, id_Qk}
	commitmentValuePolyIDs := make([]int, 0, len(s.commitmentInfo))
	for i := range s.commitmentInfo {
		commitmentValuePolyIDs = append(commitmentValuePolyIDs, id_Qci+2*i+1)
	}
	quotientDynamicPolyIDs := append(append([]int(nil), dynamicPolyIDs...), commitmentValuePolyIDs...)
	dynamicTransformCacheKey := nextCacheKey(&quotientTransformCacheKey)

	vectorBytes := int(n) * frBytes
	commitmentCount := len(quotientDynamicPolyIDs) - quotientBaseDynamicVectorCount
	if commitmentCount < 0 {
		return nil, fmt.Errorf("webgpu plonk bls12_381: quotient evaluator expected at least %d dynamic vectors, got %d", quotientBaseDynamicVectorCount, len(quotientDynamicPolyIDs))
	}
	staticVectorCount := quotientBaseStaticVectorCount + commitmentCount
	staticInputs, err := s.pk.quotientStaticBridgeInputs(rho, staticVectorCount, commitmentCount, int(n), vectorBytes)
	if err != nil {
		return nil, err
	}
	quotientAux := staticInputs.quotientAux

	dynamicPacked := make([]byte, len(quotientDynamicPolyIDs)*vectorBytes)
	for i, id := range quotientDynamicPolyIDs {
		if id >= len(s.x) || s.x[id] == nil {
			return nil, fmt.Errorf("webgpu plonk bls12_381: missing quotient dynamic polynomial %d", id)
		}
		coeffs := s.x[id].Coefficients()
		if len(coeffs) != int(n) {
			return nil, fmt.Errorf("webgpu plonk bls12_381: quotient dynamic polynomial %d has %d coefficients, expected %d", id, len(coeffs), n)
		}
		packFrVectorRegularLEInto(dynamicPacked[i*vectorBytes:(i+1)*vectorBytes], coeffs)
	}

	blinds := [][]fr.Element{
		s.bp[id_Bl].Coefficients(),
		s.bp[id_Br].Coefficients(),
		s.bp[id_Bo].Coefficients(),
		s.bp[id_Bz].Coefficients(),
	}
	blindCoeffCount := 0
	for _, blind := range blinds {
		if len(blind) > blindCoeffCount {
			blindCoeffCount = len(blind)
		}
	}

	blindBytes := len(blinds) * blindCoeffCount * frBytes
	blindsPacked := make([]byte, rho*blindBytes)
	scalarBytes := quotientEvalScalarCount * frBytes
	scalarsPacked := make([]byte, rho*scalarBytes)

	for i := 0; i < rho; i++ {
		coset := quotientAux.cosets[i]
		cosetExpMinusOne := quotientAux.cosetExpMinusOnes[i]
		blindStart := i * blindBytes
		for blindIndex, blind := range blinds {
			start := blindStart + blindIndex*blindCoeffCount*frBytes
			acc := cosetExpMinusOne
			for j := range blind {
				var scaled fr.Element
				scaled.Mul(&blind[j], &acc)
				writeFrRegularLE(blindsPacked[start+j*frBytes:start+(j+1)*frBytes], &scaled)
				acc.Mul(&acc, &coset)
			}
		}

		packFrVectorRegularLEInto(scalarsPacked[i*scalarBytes:(i+1)*scalarBytes], []fr.Element{
			coset,
			quotientAux.lagrangeScales[i],
			quotientAux.cs,
			quotientAux.css,
			s.beta,
			s.gamma,
			s.alpha,
		})
	}

	outputPacked, err := bridge.Bridge.TransformAndEvaluateQuotientCosets(
		"bls12_381",
		dynamicPacked,
		staticInputs.scalingPacked,
		staticInputs.staticPacked,
		staticInputs.staticMontCacheKeysPacked,
		staticInputs.twiddlesPacked,
		staticInputs.denominatorsPacked,
		blindsPacked,
		scalarsPacked,
		int(n),
		blindCoeffCount,
		commitmentCount,
		dynamicTransformCacheKey,
		rho,
		staticInputs.auxMontCacheKey,
	)
	if err != nil {
		return nil, err
	}
	if len(outputPacked) != rho*vectorBytes {
		return nil, fmt.Errorf("webgpu plonk bls12_381: quotient all-coset evaluator returned %d bytes, expected %d", len(outputPacked), rho*vectorBytes)
	}
	s.pk.markQuotientStaticBridgeInputsPopulated(staticInputs.staticCache)
	for i := 0; i < rho; i++ {
		if err := unpackFrVectorRegularLEInto(buf, outputPacked[i*vectorBytes:(i+1)*vectorBytes]); err != nil {
			return nil, err
		}
		for j := 0; j < int(n); j++ {
			// we build the polynomial in bit reverse order
			cres[bits.Reverse64(uint64(rho*j+i))>>mm] = buf[j]
		}
	}

	canonicalizeGroup := func(ids []int) error {
		polys := make([]*iop.Polynomial, 0, len(ids))
		for _, id := range ids {
			if id >= len(s.x) || id == id_ZS || s.x[id] == nil {
				continue
			}
			polys = append(polys, s.x[id])
		}
		if err := canonicalizePolynomialsRegularWithWebGPU(polys, int(s.domain0.Cardinality)); err != nil {
			return err
		}
		return nil
	}

	s.x[id_ZS] = nil
	s.x[id_Qk] = nil

	if err := canonicalizeGroup(dynamicPolyIDs); err != nil {
		return nil, err
	}
	if len(commitmentValuePolyIDs) > 0 {
		if err := canonicalizeGroup(commitmentValuePolyIDs); err != nil {
			return nil, err
		}
	}

	res := iop.NewPolynomial(&cres, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse})

	return res, nil

}

func evaluateBlinded(p, bp *iop.Polynomial, zeta fr.Element) fr.Element {
	// Get the size of the polynomial
	n := big.NewInt(int64(p.Size()))

	var pEvaluatedAtZeta fr.Element

	// Evaluate the polynomial and blinded polynomial at zeta
	pEvaluatedAtZeta = p.Evaluate(zeta)
	bpEvaluatedAtZeta := bp.Evaluate(zeta)

	// Multiply the evaluated blinded polynomial by tempElement
	var t fr.Element
	one := fr.One()
	t.Exp(zeta, n).Sub(&t, &one)
	bpEvaluatedAtZeta.Mul(&bpEvaluatedAtZeta, &t)

	// Add the evaluated polynomial and the evaluated blinded polynomial
	pEvaluatedAtZeta.Add(&pEvaluatedAtZeta, &bpEvaluatedAtZeta)

	// Return the result
	return pEvaluatedAtZeta
}

// /!\ modifies the size
func getBlindedCoefficients(p, bp *iop.Polynomial) []fr.Element {
	cp := p.Coefficients()
	cbp := bp.Coefficients()
	cp = append(cp, cbp...)
	for i := 0; i < len(cbp); i++ {
		cp[i].Sub(&cp[i], &cbp[i])
	}
	return cp
}

// commits to a polynomial of the form b*(Xⁿ-1) where b is of small degree
func commitBlindingFactor(n int, b *iop.Polynomial, key kzg.ProvingKey) curve.G1Affine {
	cp := b.Coefficients()
	np := b.Size()

	var res curve.G1Affine
	for i := 0; i < np; i++ {
		var scalar big.Int
		cp[i].BigInt(&scalar)

		var hi, lo curve.G1Affine
		hi.ScalarMultiplication(&key.G1[n+i], &scalar)
		lo.ScalarMultiplication(&key.G1[i], &scalar)
		hi.Sub(&hi, &lo)
		res.Add(&res, &hi)
	}
	return res
}

func evalKZGPolynomial(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	for i := len(p) - 1; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}

// dividePolyByXMinusA computes (f-f(a))/(x-a), reusing f for the result.
func dividePolyByXMinusA(f []fr.Element, fa, a fr.Element) []fr.Element {
	if len(f) == 0 {
		return []fr.Element{}
	}

	f[0].Sub(&f[0], &fa)

	var t fr.Element
	for i := len(f) - 2; i >= 0; i-- {
		t.Mul(&f[i+1], &a)
		f[i].Add(&f[i], &t)
	}

	return f[1:]
}

func deriveKZGBatchGamma(point fr.Element, digests []curve.G1Affine, claimedValues []fr.Element, hf hash.Hash, dataTranscript ...[]byte) (fr.Element, error) {
	fs := fiatshamir.NewTranscript(hf, "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", claimedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range dataTranscript {
		if err := fs.Bind("gamma", dataTranscript[i]); err != nil {
			return fr.Element{}, err
		}
	}

	gammaBytes, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaBytes)
	return gamma, nil
}

// return a random polynomial of degree n, if n==-1 cancel the blinding
func getRandomPolynomial(n int) *iop.Polynomial {
	var a []fr.Element
	if n == -1 {
		a = make([]fr.Element, 1)
		a[0].SetZero()
	} else {
		a = make([]fr.Element, n+1)
		for i := 0; i <= n; i++ {
			a[i].SetRandom()
		}
	}
	res := iop.NewPolynomial(&a, iop.Form{
		Basis: iop.Canonical, Layout: iop.Regular})
	return res
}

func coefficients(p []*iop.Polynomial) [][]fr.Element {
	res := make([][]fr.Element, len(p))
	for i, pI := range p {
		res[i] = pI.Coefficients()
	}
	return res
}

func (s *instance) commitToQuotient(h1, h2, h3 []fr.Element) error {
	commits, err := s.msmG1Batch("kzg", 0, h1, h2, h3)
	if err != nil {
		return err
	}
	copy(s.proof.H[:], commits)
	return nil
}

// divideByZH
// The input must be in LagrangeCoset.
// The result is in Canonical Regular. (in place using a)
func divideByZH(a *iop.Polynomial, domains [2]*fft.Domain) (*iop.Polynomial, error) {
	smallDomain, bigDomain := domains[0], domains[1]
	if smallDomain == nil || bigDomain == nil {
		return nil, errors.New("invalid domain")
	}
	if smallDomain.Cardinality == 0 || bigDomain.Cardinality == 0 {
		return nil, errors.New("invalid domain cardinality")
	}
	if bigDomain.Cardinality%smallDomain.Cardinality != 0 {
		return nil, errors.New("invalid domain ratio")
	}

	// check that the basis is LagrangeCoset
	if a.Basis != iop.LagrangeCoset || a.Layout != iop.BitReverse {
		return nil, errors.New("invalid form")
	}

	// prepare the evaluations of x^n-1 on the big domain's coset
	xnMinusOneInverseLagrangeCoset := evaluateXnMinusOneDomainBigCoset(domains)
	rho := int(bigDomain.Cardinality / smallDomain.Cardinality)

	r := a.Coefficients()
	n := uint64(len(r))
	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := range r {
		iRev := bits.Reverse64(uint64(i)) >> nn
		r[i].Mul(&r[i], &xnMinusOneInverseLagrangeCoset[int(iRev)%rho])
	}

	if err := canonicalizeQuotientFromCosetWithWebGPU(a); err != nil {
		return nil, err
	}

	return a, nil

}

// evaluateXnMinusOneDomainBigCoset evaluates Xᵐ-1 on DomainBig coset
func evaluateXnMinusOneDomainBigCoset(domains [2]*fft.Domain) []fr.Element {

	rho := domains[1].Cardinality / domains[0].Cardinality

	res := make([]fr.Element, rho)

	expo := big.NewInt(int64(domains[0].Cardinality))
	res[0].Exp(domains[1].FrMultiplicativeGen, expo)

	var t fr.Element
	t.Exp(domains[1].Generator, expo)

	one := fr.One()

	for i := 1; i < int(rho); i++ {
		res[i].Mul(&res[i-1], &t)
		res[i-1].Sub(&res[i-1], &one)
	}
	res[len(res)-1].Sub(&res[len(res)-1], &one)

	res = fr.BatchInvert(res)

	return res
}

// innerComputeLinearizedPoly computes the linearized polynomial in canonical basis.
// The purpose is to commit and open all in one ql, qr, qm, qo, qk.
// * lZeta, rZeta, oZeta are the evaluation of l, r, o at zeta
// * z is the permutation polynomial, zu is Z(μX), the shifted version of Z
// * pk is the proving key: the linearized polynomial is a linear combination of ql, qr, qm, qo, qk.
//
// The Linearized polynomial is:
//
// α²*L₁(ζ)*Z(X)
// + α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(β*s3(X))*Z(μζ) - Z(X)*(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ))
// + l(ζ)*Ql(X) + l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X) + ∑ᵢQcp_(ζ)Pi_(X)
// - Z_{H}(ζ)*((H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
//
// /!\ blindedZCanonical is modified
func (s *instance) innerComputeLinearizedPoly(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, qcpZeta, blindedZCanonical []fr.Element, pi2Canonical [][]fr.Element, pk *ProvingKey) ([]fr.Element, error) {

	// l(ζ)r(ζ)
	var rl fr.Element
	rl.Mul(&rZeta, &lZeta)

	// s1 =  α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)
	// s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	// the linearised polynomial is
	// α²*L₁(ζ)*Z(X) +
	// s1*s3(X)+s2*Z(X) + l(ζ)*Ql(X) +
	// l(ζ)r(ζ)*Qm(X) + r(ζ)*Qr(X) + o(ζ)*Qo(X) + Qk(X) + ∑ᵢQcp_(ζ)Pi_(X) -
	// Z_{H}(ζ)*((H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
	var s1, s2 fr.Element
	s1 = s.trace.S1.Evaluate(zeta)                                   // s1(ζ)
	s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma)             // (l(ζ)+β*s1(ζ)+γ)
	tmp := s.trace.S2.Evaluate(zeta)                                 // s2(ζ)
	tmp.Mul(&tmp, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma)         // (r(ζ)+β*s2(ζ)+γ)
	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta).Mul(&s1, &alpha) // (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(μζ)*α

	var uzeta, uuzeta fr.Element
	uzeta.Mul(&zeta, &pk.Vk.CosetShift)
	uuzeta.Mul(&uzeta, &pk.Vk.CosetShift)

	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)      // (l(ζ)+β*ζ+γ)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)  // (r(ζ)+β*u*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma) // (o(ζ)+β*u²*ζ+γ)
	s2.Mul(&s2, &tmp)                                           // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	s2.Neg(&s2).Mul(&s2, &alpha)

	// Z_h(ζ), ζⁿ⁺², L₁(ζ)*α²*Z
	var zhZeta, zetaNPlusTwo, alphaSquareLagrangeZero, one, den, frNbElmt fr.Element
	one.SetOne()
	nbElmt := int64(s.domain0.Cardinality)
	alphaSquareLagrangeZero.Set(&zeta).Exp(alphaSquareLagrangeZero, big.NewInt(nbElmt)) // ζⁿ
	zetaNPlusTwo.Mul(&alphaSquareLagrangeZero, &zeta).Mul(&zetaNPlusTwo, &zeta)         // ζⁿ⁺²
	alphaSquareLagrangeZero.Sub(&alphaSquareLagrangeZero, &one)                         // ζⁿ - 1
	zhZeta.Set(&alphaSquareLagrangeZero)                                                // Z_h(ζ) = ζⁿ - 1
	frNbElmt.SetUint64(uint64(nbElmt))
	den.Sub(&zeta, &one).Inverse(&den)                           // 1/(ζ-1)
	alphaSquareLagrangeZero.Mul(&alphaSquareLagrangeZero, &den). // L₁ = (ζⁿ - 1)/(ζ-1)
									Mul(&alphaSquareLagrangeZero, &alpha).
									Mul(&alphaSquareLagrangeZero, &alpha).
									Mul(&alphaSquareLagrangeZero, &s.domain0.CardinalityInv) // α²*L₁(ζ)

	s3canonical := s.trace.S3.Coefficients()

	if err := canonicalizePolynomialsRegularWithWebGPU([]*iop.Polynomial{s.trace.Qk}, int(s.domain0.Cardinality)); err != nil {
		return nil, err
	}

	// len(h1)=len(h2)=len(blindedZCanonical)=len(h3)+1 when Statistical ZK is activated
	// len(h1)=len(h2)=len(h3)=len(blindedZCanonical)-1 when Statistical ZK is deactivated
	h1 := s.h1()
	h2 := s.h2()
	h3 := s.h3()

	// at this stage we have
	// s1 =  α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)
	// s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	cql := s.trace.Ql.Coefficients()
	cqr := s.trace.Qr.Coefficients()
	cqm := s.trace.Qm.Coefficients()
	cqo := s.trace.Qo.Coefficients()
	cqk := s.trace.Qk.Coefficients()

	var t, t0, t1 fr.Element

	for i := range blindedZCanonical {
		t.Mul(&blindedZCanonical[i], &s2) // -Z(X)*α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
		if i < len(s3canonical) {
			t0.Mul(&s3canonical[i], &s1) // α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)*β*s3(X)
			t.Add(&t, &t0)
		}
		if i < len(cqm) {
			t1.Mul(&cqm[i], &rl)     // l(ζ)r(ζ)*Qm(X)
			t.Add(&t, &t1)           // linPol += l(ζ)r(ζ)*Qm(X)
			t0.Mul(&cql[i], &lZeta)  // l(ζ)Q_l(X)
			t.Add(&t, &t0)           // linPol += l(ζ)*Ql(X)
			t0.Mul(&cqr[i], &rZeta)  //r(ζ)*Qr(X)
			t.Add(&t, &t0)           // linPol += r(ζ)*Qr(X)
			t0.Mul(&cqo[i], &oZeta)  // o(ζ)*Qo(X)
			t.Add(&t, &t0)           // linPol += o(ζ)*Qo(X)
			t.Add(&t, &cqk[i])       // linPol += Qk(X)
			for j := range qcpZeta { // linPol += ∑ᵢQcp_(ζ)Pi_(X)
				t0.Mul(&pi2Canonical[j][i], &qcpZeta[j])
				t.Add(&t, &t0)
			}
		}

		t0.Mul(&blindedZCanonical[i], &alphaSquareLagrangeZero) // α²L₁(ζ)Z(X)
		blindedZCanonical[i].Add(&t, &t0)                       // linPol += α²L₁(ζ)Z(X)

		// if statistical zeroknowledge is deactivated, len(h1)=len(h2)=len(h3)=len(blindedZ)-1.
		// Else len(h1)=len(h2)=len(blindedZCanonical)=len(h3)+1
		if i < len(h3) {
			t.Mul(&h3[i], &zetaNPlusTwo).
				Add(&t, &h2[i]).
				Mul(&t, &zetaNPlusTwo).
				Add(&t, &h1[i]).
				Mul(&t, &zhZeta)
			blindedZCanonical[i].Sub(&blindedZCanonical[i], &t) // linPol -= Z_h(ζ)*(H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
		} else if s.opt.StatisticalZK {
			t.Mul(&h2[i], &zetaNPlusTwo).
				Add(&t, &h1[i]).
				Mul(&t, &zhZeta)
			blindedZCanonical[i].Sub(&blindedZCanonical[i], &t) // linPol -= Z_h(ζ)*(H₀(X) + ζᵐ⁺²*H₁(X) + ζ²⁽ᵐ⁺²⁾*H₂(X))
		}
	}

	return blindedZCanonical, nil
}

func bindPublicData(fs *fiatshamir.Transcript, challenge string, vk *native.VerifyingKey, publicInputs []fr.Element) error {
	if err := fs.Bind(challenge, vk.S[0].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[1].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[2].Marshal()); err != nil {
		return err
	}

	if err := fs.Bind(challenge, vk.Ql.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qr.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qm.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qo.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qk.Marshal()); err != nil {
		return err
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, vk.Qcp[i].Marshal()); err != nil {
			return err
		}
	}

	for i := 0; i < len(publicInputs); i++ {
		if err := fs.Bind(challenge, publicInputs[i].Marshal()); err != nil {
			return err
		}
	}

	return nil
}

func deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...*curve.G1Affine) (fr.Element, error) {
	var buf [curve.SizeOfG1AffineUncompressed]byte
	var r fr.Element

	for _, p := range points {
		buf = p.RawBytes()
		if err := fs.Bind(challenge, buf[:]); err != nil {
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
