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
	"context"
	"crypto/sha256"
	"errors"
	"golang.org/x/sync/errgroup"
	"hash"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark/backend/witness"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/fft"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/iop"
	cs "github.com/consensys/gnark/constraint/bls12-377"

	"github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
)

// TODO in gnark-crypto:
// * remove everything linked to the blinding
// * add SetCoeff method
// * modify GetCoeff -> if the poly is shifted and in canonical form the index is computed differently

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
	id_ID
	id_LOne
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

type Proof struct {

	// Commitments to the solution vectors
	LRO [3]kzg.Digest

	// Commitment to Z, the permutation polynomial
	Z kzg.Digest

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Digest

	Bsb22Commitments []kzg.Digest

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2, qCPrime
	BatchedProof kzg.BatchOpeningProof

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof
}

func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {

	log := logger.Logger().With().
		Str("curve", spr.CurveID().String()).
		Int("nbConstraints", spr.GetNbConstraints()).
		Str("backend", "plonk").Logger()

	// parse the options
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	// init instance
	g, ctx := errgroup.WithContext(context.Background())
	instance := newInstance(ctx, spr, pk, fullWitness, &opt)

	// solve constraints
	g.Go(instance.solveConstraints)

	// complete qk
	g.Go(instance.completeQk)

	// init blinding polynomials
	g.Go(instance.initBlindingPolynomials)

	// derive gamma, beta (copy constraint)
	g.Go(instance.deriveGammaAndBeta)

	// compute accumulating ratio for the copy constraint
	g.Go(instance.buildRatioCopyConstraint)

	// compute h
	g.Go(instance.evaluateConstraints)

	// open Z (blinded) at ωζ (proof.ZShiftedOpening)
	g.Go(instance.openZ)

	// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
	g.Go(instance.foldH)

	// linearized polynomial
	g.Go(instance.computeLinearizedPolynomial)

	// Batch opening
	g.Go(instance.batchOpening)

	if err := g.Wait(); err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")
	return instance.proof, nil
}

// represents a Prover instance
type instance struct {
	ctx context.Context

	pk    *ProvingKey
	proof *Proof
	spr   *cs.SparseR1CS
	opt   *backend.ProverConfig

	fs    fiatshamir.Transcript
	hFunc hash.Hash

	// polynomials
	x        []*iop.Polynomial // x stores tracks the polynomial we need
	bp       []*iop.Polynomial // blinding polynomials
	h        *iop.Polynomial   // h is the quotient polynomial
	blindedZ []fr.Element      // blindedZ is the blinded version of Z

	foldedH       []fr.Element // foldedH is the folded version of H
	foldedHDigest kzg.Digest   // foldedHDigest is the kzg commitment of foldedH

	linearizedPolynomial       []fr.Element
	linearizedPolynomialDigest kzg.Digest

	fullWitness witness.Witness

	// bsb22 commitment stuff
	commitmentInfo constraint.PlonkCommitments
	commitmentVal  []fr.Element
	cCommitments   []*iop.Polynomial

	// challenges
	gamma, beta, alpha, zeta fr.Element

	// channel to wait for the steps
	chLRO,
	chQk,
	chbp,
	chZ,
	chH,
	chZOpening,
	chLinearizedPolynomial,
	chFoldedH,
	chGammaBeta chan struct{}
}

func newInstance(ctx context.Context, spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts *backend.ProverConfig) instance {
	hFunc := sha256.New()
	s := instance{
		ctx:                    ctx,
		pk:                     pk,
		proof:                  &Proof{},
		spr:                    spr,
		opt:                    opts,
		fullWitness:            fullWitness,
		bp:                     make([]*iop.Polynomial, nb_blinding_polynomials),
		fs:                     fiatshamir.NewTranscript(hFunc, "gamma", "beta", "alpha", "zeta"),
		hFunc:                  hFunc,
		chLRO:                  make(chan struct{}, 1),
		chQk:                   make(chan struct{}, 1),
		chbp:                   make(chan struct{}, 1),
		chGammaBeta:            make(chan struct{}, 1),
		chZ:                    make(chan struct{}, 1),
		chH:                    make(chan struct{}, 1),
		chZOpening:             make(chan struct{}, 1),
		chLinearizedPolynomial: make(chan struct{}, 1),
		chFoldedH:              make(chan struct{}, 1),
	}
	s.initBSB22Commitments()
	s.setupGKRHints()
	s.x = make([]*iop.Polynomial, id_Qci+2*len(s.commitmentInfo))

	return s
}

func (s *instance) initBlindingPolynomials() error {
	s.bp[id_Bl] = getRandomPolynomial(order_blinding_L)
	s.bp[id_Br] = getRandomPolynomial(order_blinding_R)
	s.bp[id_Bo] = getRandomPolynomial(order_blinding_O)
	s.bp[id_Bz] = getRandomPolynomial(order_blinding_Z)
	close(s.chbp)
	return nil
}

func (s *instance) initBSB22Commitments() {
	s.commitmentInfo = s.spr.CommitmentInfo.(constraint.PlonkCommitments)
	s.commitmentVal = make([]fr.Element, len(s.commitmentInfo)) // TODO @Tabaie get rid of this
	s.cCommitments = make([]*iop.Polynomial, len(s.commitmentInfo))
	s.proof.Bsb22Commitments = make([]kzg.Digest, len(s.commitmentInfo))

	// override the hint for the commitment constraints
	for i := range s.commitmentInfo {
		s.opt.SolverOpts = append(s.opt.SolverOpts,
			solver.OverrideHint(s.commitmentInfo[i].HintID, s.bsb22Hint(i)))
	}
}

// Computing and verifying Bsb22 multi-commits explained in https://hackmd.io/x8KsadW3RRyX7YTCFJIkHg
func (s *instance) bsb22Hint(commDepth int) solver.Hint {
	return func(_ *big.Int, ins, outs []*big.Int) error {
		res := &s.commitmentVal[commDepth]

		commitmentInfo := s.spr.CommitmentInfo.(constraint.PlonkCommitments)[commDepth]
		committedValues := make([]fr.Element, s.pk.Domain[0].Cardinality)
		offset := s.spr.GetNbPublicVariables()
		for i := range ins {
			committedValues[offset+commitmentInfo.Committed[i]].SetBigInt(ins[i])
		}
		var (
			err     error
			hashRes []fr.Element
		)
		if _, err = committedValues[offset+commitmentInfo.CommitmentIndex].SetRandom(); err != nil { // Commitment injection constraint has qcp = 0. Safe to use for blinding.
			return err
		}
		if _, err = committedValues[offset+s.spr.GetNbConstraints()-1].SetRandom(); err != nil { // Last constraint has qcp = 0. Safe to use for blinding
			return err
		}
		s.cCommitments[commDepth] = iop.NewPolynomial(&committedValues, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		s.cCommitments[commDepth].ToCanonical(&s.pk.Domain[0]).ToRegular()
		if s.proof.Bsb22Commitments[commDepth], err = kzg.Commit(s.cCommitments[commDepth].Coefficients(), s.pk.Kzg); err != nil {
			return err
		}
		if hashRes, err = fr.Hash(s.proof.Bsb22Commitments[commDepth].Marshal(), []byte("BSB22-Plonk"), 1); err != nil {
			return err
		}
		res.Set(&hashRes[0]) // TODO @Tabaie use CommitmentIndex for this; create a new variable CommitmentConstraintIndex for other uses
		res.BigInt(outs[0])

		return nil
	}
}

func (s *instance) setupGKRHints() {
	if s.spr.GkrInfo.Is() {
		var gkrData cs.GkrSolvingData
		s.opt.SolverOpts = append(s.opt.SolverOpts,
			solver.OverrideHint(s.spr.GkrInfo.SolveHintID, cs.GkrSolveHint(s.spr.GkrInfo, &gkrData)),
			solver.OverrideHint(s.spr.GkrInfo.ProveHintID, cs.GkrProveHint(s.spr.GkrInfo.HashName, &gkrData)))
	}
}

// solveConstraints computes the evaluation of the polynomials L, R, O
// and sets x[id_L], x[id_R], x[id_O] in canonical form
func (s *instance) solveConstraints() error {
	_solution, err := s.spr.Solve(s.fullWitness, s.opt.SolverOpts...)
	if err != nil {
		return err
	}
	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		s.x[id_L] = iop.NewPolynomial(&evaluationLDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}).
			ToCanonical(&s.pk.Domain[0]).
			ToRegular()
		wg.Done()
	}()
	go func() {
		s.x[id_R] = iop.NewPolynomial(&evaluationRDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}).
			ToCanonical(&s.pk.Domain[0]).
			ToRegular()
		wg.Done()
	}()

	s.x[id_O] = iop.NewPolynomial(&evaluationODomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}).
		ToCanonical(&s.pk.Domain[0]).
		ToRegular()

	wg.Wait()

	// commit to l, r, o and add blinding factors
	if err := s.commitToLRO(); err != nil {
		return err
	}
	close(s.chLRO)
	return nil
}

func (s *instance) completeQk() error {
	qk := s.pk.trace.Qk.Clone().ToLagrange(&s.pk.Domain[0]).ToRegular()
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
	close(s.chQk)

	return nil
}

func (s *instance) commitToLRO() error {
	// wait for blinding polynomials to be initialized or context to be done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chbp:
	}

	g := new(errgroup.Group)

	g.Go(func() (err error) {
		s.proof.LRO[0], err = s.commitToPolyAndBlinding(s.x[id_L], s.bp[id_Bl])
		return
	})

	g.Go(func() (err error) {
		s.proof.LRO[1], err = s.commitToPolyAndBlinding(s.x[id_R], s.bp[id_Br])
		return
	})

	g.Go(func() (err error) {
		s.proof.LRO[2], err = s.commitToPolyAndBlinding(s.x[id_O], s.bp[id_Bo])
		return
	})

	return g.Wait()
}

// deriveGammaAndBeta (copy constraint)
func (s *instance) deriveGammaAndBeta() error {
	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return witness.ErrInvalidWitness
	}

	if err := bindPublicData(&s.fs, "gamma", s.pk.Vk, wWitness[:len(s.spr.Public)]); err != nil {
		return err
	}

	// wait for LRO to be committed
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	gamma, err := deriveRandomness(&s.fs, "gamma", &s.proof.LRO[0], &s.proof.LRO[1], &s.proof.LRO[2])
	if err != nil {
		return err
	}

	bbeta, err := s.fs.ComputeChallenge("beta")
	if err != nil {
		return err
	}
	s.gamma = gamma
	s.beta.SetBytes(bbeta)

	close(s.chGammaBeta)

	return nil
}

// commitToPolyAndBlinding computes the KZG commitment of a polynomial p (large degree)
// and add the contribution of a blinding polynomial b (small degree)
func (s *instance) commitToPolyAndBlinding(p, b *iop.Polynomial) (commit curve.G1Affine, err error) {
	// first we compute the commit contribution of p
	commit, err = kzg.Commit(p.Coefficients(), s.pk.Kzg)
	if err != nil {
		return
	}

	// we add in the blinding contribution
	n := int(s.pk.Domain[0].Cardinality)
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
	s.alpha, err = deriveRandomness(&s.fs, "alpha", alphaDeps...)
	return err
}

func (s *instance) deriveZeta() (err error) {
	s.zeta, err = deriveRandomness(&s.fs, "zeta", &s.proof.H[0], &s.proof.H[1], &s.proof.H[2])
	return
}

// evaluateConstraints computes H
func (s *instance) evaluateConstraints() (err error) {
	// wait for Z to be committed or context done
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chZ:
	}

	// derive alpha
	if err = s.deriveAlpha(); err != nil {
		return err
	}

	n := s.pk.Domain[0].Cardinality
	// TODO complete waste of memory find another way to do that
	identity := make([]fr.Element, n)
	identity[1].Set(&s.beta)

	lone := make([]fr.Element, n)
	lone[0].SetOne()
	// TODO @gbotrel we mutate pk in computeNumerator, not safe.
	s.x[id_Ql] = s.pk.trace.Ql
	s.x[id_Qr] = s.pk.trace.Qr
	s.x[id_Qm] = s.pk.trace.Qm
	s.x[id_Qo] = s.pk.trace.Qo
	s.x[id_ZS] = s.x[id_Z].ShallowClone().Shift(1)
	s.x[id_S1] = s.pk.trace.S1
	s.x[id_S2] = s.pk.trace.S2
	s.x[id_S3] = s.pk.trace.S3
	s.x[id_ID] = iop.NewPolynomial(&identity, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	s.x[id_LOne] = iop.NewPolynomial(&lone, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	for i := 0; i < len(s.commitmentInfo); i++ {
		s.x[id_Qci+2*i] = s.pk.trace.Qcp[i]
		s.x[id_Qci+2*i+1] = s.cCommitments[i]
	}

	numerator, err := computeNumerator(s.pk, s.x, s.bp, s.alpha, s.beta, s.gamma)
	if err != nil {
		return err
	}

	s.h, err = divideByXMinusOne(numerator, [2]*fft.Domain{&s.pk.Domain[0], &s.pk.Domain[1]})
	if err != nil {
		return err
	}

	// commit to h
	if err := commitToQuotient(s.h1(), s.h2(), s.h3(), s.proof, s.pk.Kzg); err != nil {
		return err
	}

	if err := s.deriveZeta(); err != nil {
		return err
	}

	close(s.chH)

	return nil
}

func (s *instance) buildRatioCopyConstraint() (err error) {
	// wait for gamma and beta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chGammaBeta:
	}

	s.x[id_Z], err = iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{
			s.x[id_L],
			s.x[id_R],
			s.x[id_O],
		},
		s.pk.trace.S,
		s.beta,
		s.gamma,
		iop.Form{Basis: iop.Canonical, Layout: iop.Regular},
		&s.pk.Domain[0],
	)
	if err != nil {
		return err
	}

	// commit to the blinded version of z
	s.proof.Z, err = s.commitToPolyAndBlinding(s.x[id_Z], s.bp[id_Bz])

	close(s.chZ)

	return
}

// open Z (blinded) at ωζ
func (s *instance) openZ() (err error) {
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}
	var zetaShifted fr.Element
	zetaShifted.Mul(&s.zeta, &s.pk.Vk.Generator)
	s.blindedZ = getBlindedCoefficients(s.x[id_Z], s.bp[id_Bz])
	// open z at zeta
	s.proof.ZShiftedOpening, err = kzg.Open(s.blindedZ, zetaShifted, s.pk.Kzg)
	if err != nil {
		return err
	}
	close(s.chZOpening)
	return nil
}

func (s *instance) h1() []fr.Element {
	h1 := s.h.Coefficients()[:s.pk.Domain[0].Cardinality+2]
	return h1
}

func (s *instance) h2() []fr.Element {
	h2 := s.h.Coefficients()[s.pk.Domain[0].Cardinality+2 : 2*(s.pk.Domain[0].Cardinality+2)]
	return h2
}

func (s *instance) h3() []fr.Element {
	h3 := s.h.Coefficients()[2*(s.pk.Domain[0].Cardinality+2) : 3*(s.pk.Domain[0].Cardinality+2)]
	return h3
}

// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
func (s *instance) foldH() error {
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}
	var n big.Int
	n.SetUint64(s.pk.Domain[0].Cardinality + 2)

	var zetaPowerNplusTwo fr.Element
	zetaPowerNplusTwo.Exp(s.zeta, &n)
	zetaPowerNplusTwo.BigInt(&n)

	s.foldedHDigest.ScalarMultiplication(&s.proof.H[2], &n)
	s.foldedHDigest.Add(&s.foldedHDigest, &s.proof.H[1])       // ζᵐ⁺²*Comm(h3)
	s.foldedHDigest.ScalarMultiplication(&s.foldedHDigest, &n) // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2)
	s.foldedHDigest.Add(&s.foldedHDigest, &s.proof.H[0])

	// fold H (H₀ + ζᵐ⁺²*H₁ + ζ²⁽ᵐ⁺²⁾H₂))
	h1 := s.h1()
	h2 := s.h2()
	s.foldedH = s.h3()

	for i := 0; i < int(s.pk.Domain[0].Cardinality)+2; i++ {
		s.foldedH[i].
			Mul(&s.foldedH[i], &zetaPowerNplusTwo).
			Add(&s.foldedH[i], &h2[i]).
			Mul(&s.foldedH[i], &zetaPowerNplusTwo).
			Add(&s.foldedH[i], &h1[i])
	}

	close(s.chFoldedH)

	return nil
}

func (s *instance) computeLinearizedPolynomial() error {
	// wait for H to be committed and zeta to be derived (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chH:
	}

	qcpzeta := make([]fr.Element, len(s.commitmentInfo))
	// TODO @gbotrel parallelize?
	blzeta := evaluateBlinded(s.x[id_L], s.bp[id_Bl], s.zeta) // x[id_L].ToRegular().Evaluate(zeta)
	brzeta := evaluateBlinded(s.x[id_R], s.bp[id_Br], s.zeta) // x[id_R].ToRegular().Evaluate(zeta)
	bozeta := evaluateBlinded(s.x[id_O], s.bp[id_Bo], s.zeta) // x[id_O].ToRegular().Evaluate(zeta)
	for i := 0; i < len(s.commitmentInfo); i++ {
		// TODO @gbotrel mutates pk.
		qcpzeta[i] = s.pk.trace.Qcp[i].Clone().ToRegular().Evaluate(s.zeta)
	}

	// wait for Z to be opened at zeta (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chZOpening:
	}
	bzuzeta := s.proof.ZShiftedOpening.ClaimedValue

	s.linearizedPolynomial = computeLinearizedPolynomial(
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

	var err error
	s.linearizedPolynomialDigest, err = kzg.Commit(s.linearizedPolynomial, s.pk.Kzg, runtime.NumCPU()*2)
	if err != nil {
		return err
	}
	close(s.chLinearizedPolynomial)
	return nil
}

func (s *instance) batchOpening() error {
	polysQcp := coefficients(s.pk.trace.Qcp)
	polysToOpen := make([][]fr.Element, 7+len(polysQcp))
	copy(polysToOpen[7:], polysQcp)

	// wait for LRO to be committed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLRO:
	}

	// wait for foldedH to be computed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chFoldedH:
	}

	// wait for linearizedPolynomial to be computed (or ctx.Done())
	select {
	case <-s.ctx.Done():
		return errContextDone
	case <-s.chLinearizedPolynomial:
	}

	polysToOpen[0] = s.foldedH
	polysToOpen[1] = s.linearizedPolynomial
	polysToOpen[2] = getBlindedCoefficients(s.x[id_L], s.bp[id_Bl])
	polysToOpen[3] = getBlindedCoefficients(s.x[id_R], s.bp[id_Br])
	polysToOpen[4] = getBlindedCoefficients(s.x[id_O], s.bp[id_Bo])
	polysToOpen[5] = s.pk.trace.S1.Coefficients()
	polysToOpen[6] = s.pk.trace.S2.Coefficients()

	digestsToOpen := make([]curve.G1Affine, len(s.pk.Vk.Qcp)+7)
	copy(digestsToOpen[7:], s.pk.Vk.Qcp)

	digestsToOpen[0] = s.foldedHDigest
	digestsToOpen[1] = s.linearizedPolynomialDigest
	digestsToOpen[2] = s.proof.LRO[0]
	digestsToOpen[3] = s.proof.LRO[1]
	digestsToOpen[4] = s.proof.LRO[2]
	digestsToOpen[5] = s.pk.Vk.S[0]
	digestsToOpen[6] = s.pk.Vk.S[1]

	var err error
	s.proof.BatchedProof, err = kzg.BatchOpenSinglePoint(
		polysToOpen,
		digestsToOpen,
		s.zeta,
		s.hFunc,
		s.pk.Kzg,
	)

	return err
}

// evaluate the full set of constraints, all polynomials in x are back in
// canonical regular form at the end
func computeNumerator(pk *ProvingKey, x []*iop.Polynomial, bp []*iop.Polynomial, alpha, beta, gamma fr.Element) (*iop.Polynomial, error) {

	// instead of scaling S1, S2 and S3 here we do it in
	// orderingConstraint; may need to restore this;
	// TODO @gbotrel original thought was; let's not mutate the proving key,
	// and pay the cost of scaling rho times instead.
	// but it seems wwe mutated S1, S2 and S3 anyway...
	// scale(x[id_S1], beta)
	// scale(x[id_S2], beta)
	// scale(x[id_S3], beta)

	cres := make([]fr.Element, pk.Domain[1].Cardinality)

	nbBsbGates := (len(x) - id_Qci + 1) >> 1

	gateConstraint := func(u ...fr.Element) fr.Element {

		var ic, tmp fr.Element

		ic.Mul(&u[id_Ql], &u[id_L])
		tmp.Mul(&u[id_Qr], &u[id_R])
		ic.Add(&ic, &tmp)
		tmp.Mul(&u[id_Qm], &u[id_L]).Mul(&tmp, &u[id_R])
		ic.Add(&ic, &tmp)
		tmp.Mul(&u[id_Qo], &u[id_O])
		ic.Add(&ic, &tmp).Add(&ic, &u[id_Qk])
		for i := 0; i < nbBsbGates; i++ {
			tmp.Mul(&u[id_Qci+2*i], &u[id_Qci+2*i+1])
			ic.Add(&ic, &tmp)
		}

		return ic
	}

	var s, ss fr.Element
	s.Set(&pk.Domain[1].FrMultiplicativeGen)
	ss.Square(&s)

	orderingConstraint := func(u ...fr.Element) fr.Element {

		var a, b, c, r, l fr.Element

		a.Add(&gamma, &u[id_L]).Add(&a, &u[id_ID])
		b.Mul(&u[id_ID], &s).Add(&b, &u[id_R]).Add(&b, &gamma)
		c.Mul(&u[id_ID], &ss).Add(&c, &u[id_O]).Add(&c, &gamma)
		r.Mul(&a, &b).Mul(&r, &c).Mul(&r, &u[id_Z])

		a.Mul(&u[id_S1], &beta)
		a.Add(&a, &u[id_L]).Add(&a, &gamma)
		b.Mul(&u[id_S2], &beta)
		b.Add(&b, &u[id_R]).Add(&b, &gamma)
		c.Mul(&u[id_S3], &beta)
		c.Add(&c, &u[id_O]).Add(&c, &gamma)
		l.Mul(&a, &b).Mul(&l, &c).Mul(&l, &u[id_ZS])

		l.Sub(&l, &r)

		return l
	}

	ratioLocalConstraint := func(u ...fr.Element) fr.Element {

		var res fr.Element
		res.SetOne()
		res.Sub(&u[id_Z], &res).Mul(&res, &u[id_LOne])

		return res
	}

	allConstraints := func(u ...fr.Element) fr.Element {
		a := gateConstraint(u...)
		b := orderingConstraint(u...)
		c := ratioLocalConstraint(u...)
		c.Mul(&c, &alpha).Add(&c, &b).Mul(&c, &alpha).Add(&c, &a)
		return c
	}

	rho := int(pk.Domain[1].Cardinality / pk.Domain[0].Cardinality)
	shifters := make([]fr.Element, rho)
	shifters[0].Set(&pk.Domain[1].FrMultiplicativeGen)
	for i := 1; i < rho; i++ {
		shifters[i].Set(&pk.Domain[1].Generator)
	}

	// stores the current coset shifter
	var coset fr.Element
	coset.SetOne()

	var tmp, one fr.Element
	one.SetOne()
	bn := big.NewInt(int64(pk.Domain[0].Cardinality))

	buf := make([]fr.Element, pk.Domain[0].Cardinality)

	// TODO @gbotrel these can be precomputed earlier
	twiddles0 := make([]fr.Element, pk.Domain[0].Cardinality)
	copy(twiddles0, pk.Domain[0].Twiddles[0])
	for i := len(pk.Domain[0].Twiddles[0]); i < len(twiddles0); i++ {
		twiddles0[i].Mul(&twiddles0[i-1], &twiddles0[1])
	}

	cosetTable := pk.Domain[0].CosetTable
	cosetTableReversed := make([]fr.Element, len(pk.Domain[0].CosetTable))
	copy(cosetTableReversed, cosetTable)
	fft.BitReverse(cosetTableReversed)

	twiddles := pk.Domain[1].Twiddles[0][:pk.Domain[0].Cardinality]
	twiddlesReversed := make([]fr.Element, pk.Domain[0].Cardinality)
	copy(twiddlesReversed, twiddles)
	fft.BitReverse(twiddlesReversed)

	for i := 0; i < rho; i++ {

		scalingVector := func(p *iop.Polynomial) []fr.Element {
			var w []fr.Element
			if i == 0 {
				if p.Layout == iop.Regular {
					w = cosetTable
				} else {
					w = cosetTableReversed
				}
			} else {
				if p.Layout == iop.Regular {
					w = twiddles
				} else {
					w = twiddlesReversed
				}
			}
			return w
		}

		coset.Mul(&coset, &shifters[i])
		tmp.Exp(coset, bn).Sub(&tmp, &one)

		batchApply(bp, func(p *iop.Polynomial) {
			// bl <- bl *( (s*ωⁱ)ⁿ-1 )s
			cp := p.Coefficients()
			for j := 0; j < len(cp); j++ {
				cp[j].Mul(&cp[j], &tmp)
			}

			scalePowers(p, shifters[i])
		})

		batchApply(x, func(p *iop.Polynomial) {
			// shift polynomials to be in the correct coset
			p.ToCanonical(&pk.Domain[0])

			// batch scale
			w := scalingVector(p)

			cp := p.Coefficients()
			// TODO @gbotrel check if parallelizing makes sense here
			for j := 0; j < len(cp); j++ {
				cp[j].Mul(&cp[j], &w[j])
			}

			// fft in the correct coset
			p.ToLagrange(&pk.Domain[0]).ToRegular()
		})

		// blind l, r, o, z
		batchApplyPair(x[:id_ZS], bp, func(p, q *iop.Polynomial) {
			blind(p, q, twiddles0)
		})

		if _, err := iop.Evaluate(
			allConstraints,
			buf,
			iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
			x...,
		); err != nil {
			return nil, err
		}
		for j := 0; j < int(pk.Domain[0].Cardinality); j++ {
			cres[rho*j+i].Set(&buf[j])
		}

		// unblind l, r, o, z
		tmp.Inverse(&tmp)
		batchApplyPair(x[:id_ZS], bp, func(p, q *iop.Polynomial) {
			unblind(p, q, twiddles0)

			// bl <- bl *( (s*ωⁱ)ⁿ-1 )s
			cq := q.Coefficients()
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &tmp)
			}
		})
	}

	// scale everything back
	batchApply(x, func(p *iop.Polynomial) {
		// TODO @gbotrel if we clone the proving key polynomials
		// we don't need to do this.
		p.ToCanonical(&pk.Domain[0]).ToRegular()
	})

	// TODO @gbotrel ; can use the precomputed inverse table
	// in the FFT domains here.
	s.Set(&shifters[0])
	for i := 1; i < len(shifters); i++ {
		s.Mul(&s, &shifters[i])
	}
	s.Inverse(&s)

	batchScalePowers(x, s)
	batchScalePowers(bp, s)

	res := iop.NewPolynomial(&cres, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.Regular})

	return res, nil

}

// computes p - b on <\omega>
func unblind(p, b *iop.Polynomial, w []fr.Element) {
	cp := p.Coefficients()

	// x.SetOne()
	n := p.Size()
	// TODO add a method SetCoeff in gnark-crypto
	if p.Layout == iop.Regular {
		utils.Parallelize(len(cp), func(start, end int) {
			var y fr.Element
			for i := start; i < end; i++ {
				y = b.Evaluate(w[i])
				cp[i].Sub(&cp[i], &y)
				// x.Mul(&x, &w)
			}
		}, runtime.NumCPU()/4)
	} else {
		nn := uint64(64 - bits.TrailingZeros(uint(n)))
		var y fr.Element
		for i := 0; i < p.Size(); i++ {
			y = b.Evaluate(w[i])
			iRev := bits.Reverse64(uint64(i)) >> nn
			cp[iRev].Sub(&cp[iRev], &y)
			// x.Mul(&x, &w)
		}
	}
}

// computes p + b on <\omega>
func blind(p, b *iop.Polynomial, w []fr.Element) {
	cp := p.Coefficients()

	n := p.Size()
	// TODO add a method SetCoeff in gnark-crypto
	if p.Layout == iop.Regular {

		utils.Parallelize(len(cp), func(start, end int) {
			var y fr.Element
			for i := start; i < end; i++ {
				y = b.Evaluate(w[i])
				cp[i].Add(&cp[i], &y)
			}
		}, runtime.NumCPU()/4)
	} else {
		nn := uint64(64 - bits.TrailingZeros(uint(n)))
		var y fr.Element
		for i := 0; i < p.Size(); i++ {
			y = b.Evaluate(w[i])
			iRev := bits.Reverse64(uint64(i)) >> nn
			cp[iRev].Add(&cp[iRev], &y)
		}
	}
}

// batchApply executes fn on all polynomials in x except x[id_ZS] in parallel.
func batchApply(x []*iop.Polynomial, fn func(*iop.Polynomial)) {
	var wg sync.WaitGroup
	for i := 0; i < len(x); i++ {
		if i == id_ZS {
			continue
		}
		wg.Add(1)
		go func(i int) {
			fn(x[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// batchApplyPair executes fn on all polynomials pairs x[i], y[i] in parallel.
func batchApplyPair(x, y []*iop.Polynomial, fn func(p, q *iop.Polynomial)) {
	var wg sync.WaitGroup
	for i := 0; i < len(x); i++ {
		wg.Add(1)
		go func(i int) {
			fn(x[i], y[i])
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func batchScalePowers(p []*iop.Polynomial, w fr.Element) {
	var wg sync.WaitGroup
	for i := 0; i < len(p); i++ {
		if i == id_ZS { // the scaling has already been done on id_Z, which points to the same coeff array
			// TODO @gbotrel this is risky;
			// input to batchScalePowers is not always x.
			continue
		}
		wg.Add(1)
		go func(i int) {
			scalePowers(p[i], w)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// p <- <p, (1, w, .., wⁿ) >
// p is supposed to be in canonical form
func scalePowers(p *iop.Polynomial, w fr.Element) {
	var acc fr.Element
	acc.SetOne()
	cp := p.Coefficients()
	for i := 0; i < p.Size(); i++ {
		cp[i].Mul(&cp[i], &acc)
		acc.Mul(&acc, &w)
	}
}

func evaluateBlinded(p, bp *iop.Polynomial, zeta fr.Element) fr.Element {
	n := p.Size()
	bn := big.NewInt(int64(n))
	var tmp, one fr.Element
	one.SetOne()
	tmp.Exp(zeta, bn).Sub(&tmp, &one)
	pz := p.Evaluate(zeta)
	bpz := bp.Evaluate(zeta)
	bpz.Mul(&bpz, &tmp)
	pz.Add(&pz, &bpz)
	return pz
}

// /!\ modifies p's underlying array of coefficients, in particular the size changes
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

	// lo
	var tmp curve.G1Affine
	tmp.MultiExp(key.G1[:np], cp, ecc.MultiExpConfig{})

	// hi
	var res curve.G1Affine
	res.MultiExp(key.G1[n:n+np], cp, ecc.MultiExpConfig{})
	res.Sub(&res, &tmp)
	return res
}

// return a random polynomial of degree n, if n==-1 cancel the blinding
func getRandomPolynomial(n int) *iop.Polynomial {
	var a []fr.Element
	if n == -1 {
		a := make([]fr.Element, 1)
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

func commitToQuotient(h1, h2, h3 []fr.Element, proof *Proof, kzgPk kzg.ProvingKey) error {
	g := new(errgroup.Group)

	g.Go(func() (err error) {
		proof.H[0], err = kzg.Commit(h1, kzgPk)
		return
	})

	g.Go(func() (err error) {
		proof.H[1], err = kzg.Commit(h2, kzgPk)
		return
	})

	g.Go(func() (err error) {
		proof.H[2], err = kzg.Commit(h3, kzgPk)
		return
	})

	return g.Wait()
}

// divideByXMinusOne
// The input must be in LagrangeCoset.
// The result is in Canonical Regular. (in place using a)
func divideByXMinusOne(a *iop.Polynomial, domains [2]*fft.Domain) (*iop.Polynomial, error) {

	// check that the basis is LagrangeCoset
	if a.Basis != iop.LagrangeCoset {
		return nil, errors.New("invalid form")
	}

	// prepare the evaluations of x^n-1 on the big domain's coset
	xnMinusOneInverseLagrangeCoset := evaluateXnMinusOneDomainBigCoset(domains)

	nbElmts := len(a.Coefficients())
	rho := int(domains[1].Cardinality / domains[0].Cardinality)

	// TODO @gbotrel this is the only place we do a FFT inverse (on coset) with domain[1]
	r := a.Coefficients()
	for i := 0; i < nbElmts; i++ {
		r[i].Mul(&r[i], &xnMinusOneInverseLagrangeCoset[i%rho])
	}

	a.ToCanonical(domains[1]).ToRegular()

	return a, nil

}

// evaluateXnMinusOneDomainBigCoset evaluates Xᵐ-1 on DomainBig coset
func evaluateXnMinusOneDomainBigCoset(domains [2]*fft.Domain) []fr.Element {

	ratio := domains[1].Cardinality / domains[0].Cardinality

	res := make([]fr.Element, ratio)

	expo := big.NewInt(int64(domains[0].Cardinality))
	res[0].Exp(domains[1].FrMultiplicativeGen, expo)

	var t fr.Element
	t.Exp(domains[1].Generator, big.NewInt(int64(domains[0].Cardinality)))

	one := fr.One()

	for i := 1; i < int(ratio); i++ {
		res[i].Mul(&res[i-1], &t)
		res[i-1].Sub(&res[i-1], &one)
	}
	res[len(res)-1].Sub(&res[len(res)-1], &one)

	res = fr.BatchInvert(res)

	return res
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
func computeLinearizedPolynomial(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, qcpZeta, blindedZCanonical []fr.Element, pi2Canonical [][]fr.Element, pk *ProvingKey) []fr.Element {

	// first part: individual constraints
	var rl fr.Element
	rl.Mul(&rZeta, &lZeta)

	// second part:
	// Z(μζ)(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*s3(X)-Z(X)(l(ζ)+β*id1(ζ)+γ)*(r(ζ)+β*id2(ζ)+γ)*(o(ζ)+β*id3(ζ)+γ)
	var s1, s2 fr.Element
	chS1 := make(chan struct{}, 1)
	go func() {
		s1 = pk.trace.S1.Evaluate(zeta)                      // s1(ζ)
		s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma) // (l(ζ)+β*s1(ζ)+γ)
		close(chS1)
	}()
	// ps2 := iop.NewPolynomial(&pk.S2Canonical, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	tmp := pk.trace.S2.Evaluate(zeta)                        // s2(ζ)
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

	s3canonical := pk.trace.S3.Coefficients()

	utils.Parallelize(len(blindedZCanonical), func(start, end int) {

		cql := pk.trace.Ql.Coefficients()
		cqr := pk.trace.Qr.Coefficients()
		cqm := pk.trace.Qm.Coefficients()
		cqo := pk.trace.Qo.Coefficients()
		cqk := pk.trace.Qk.Coefficients()

		var t, t0, t1 fr.Element

		for i := start; i < end; i++ {

			t.Mul(&blindedZCanonical[i], &s2) // -Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

			if i < len(s3canonical) {

				t0.Mul(&s3canonical[i], &s1) // (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*β*s3(X)

				t.Add(&t, &t0)
			}

			t.Mul(&t, &alpha) // α*( (l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*Z(μζ)*s3(X) - Z(X)*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ))

			if i < len(cqm) {

				t1.Mul(&cqm[i], &rl) // linPol = linPol + l(ζ)r(ζ)*Qm(X)

				t0.Mul(&cql[i], &lZeta)
				t0.Add(&t0, &t1)

				t.Add(&t, &t0) // linPol = linPol + l(ζ)*Ql(X)

				t0.Mul(&cqr[i], &rZeta)
				t.Add(&t, &t0) // linPol = linPol + r(ζ)*Qr(X)

				t0.Mul(&cqo[i], &oZeta)
				t0.Add(&t0, &cqk[i])

				t.Add(&t, &t0) // linPol = linPol + o(ζ)*Qo(X) + Qk(X)

				for j := range qcpZeta {
					t0.Mul(&pi2Canonical[j][i], &qcpZeta[j])
					t.Add(&t, &t0)
				}
			}

			t0.Mul(&blindedZCanonical[i], &lagrangeZeta)
			blindedZCanonical[i].Add(&t, &t0) // finish the computation
		}
	})
	return blindedZCanonical
}

var errContextDone = errors.New("context done")
