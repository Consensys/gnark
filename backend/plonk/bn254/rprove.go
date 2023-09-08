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
	"errors"
	"math/big"
	"math/bits"
	"runtime"
	"time"

	"github.com/consensys/gnark/backend/witness"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	cs "github.com/consensys/gnark/constraint/bn254"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
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
	id_Ql int = iota
	id_Qr
	id_Qm
	id_Qo
	id_Qk
	id_L
	id_R
	id_O
	id_Z
	id_ZS
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

// Computing and verifying Bsb22 multi-commits explained in https://hackmd.io/x8KsadW3RRyX7YTCFJIkHg
func bsb22ComputeCommitmentHint(spr *cs.SparseR1CS, pk *ProvingKey, proof *Proof, cCommitments []*iop.Polynomial, res *fr.Element, commDepth int) solver.Hint {
	return func(_ *big.Int, ins, outs []*big.Int) error {
		commitmentInfo := spr.CommitmentInfo.(constraint.PlonkCommitments)[commDepth]
		committedValues := make([]fr.Element, pk.Domain[0].Cardinality)
		offset := spr.GetNbPublicVariables()
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
		if _, err = committedValues[offset+spr.GetNbConstraints()-1].SetRandom(); err != nil { // Last constraint has qcp = 0. Safe to use for blinding
			return err
		}
		pi2iop := iop.NewPolynomial(&committedValues, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
		cCommitments[commDepth] = pi2iop.ShallowClone()
		cCommitments[commDepth].ToCanonical(&pk.Domain[0]).ToRegular()
		if proof.Bsb22Commitments[commDepth], err = kzg.Commit(cCommitments[commDepth].Coefficients(), pk.Kzg); err != nil {
			return err
		}
		if hashRes, err = fr.Hash(proof.Bsb22Commitments[commDepth].Marshal(), []byte("BSB22-Plonk"), 1); err != nil {
			return err
		}
		res.Set(&hashRes[0]) // TODO @Tabaie use CommitmentIndex for this; create a new variable CommitmentConstraintIndex for other uses
		res.BigInt(outs[0])

		return nil
	}
}

// represents a Prover instance
type instance struct {
	pk    *ProvingKey
	proof *Proof
	spr   *cs.SparseR1CS
	opt   *backend.ProverConfig
	bp    []*iop.Polynomial // blinding polynomials
	fs    *fiatshamir.Transcript
}

func (s *instance) initBlindingPolynomials() {
	s.bp[id_Bl] = getRandomPolynomial(order_blinding_L)
	s.bp[id_Br] = getRandomPolynomial(order_blinding_R)
	s.bp[id_Bo] = getRandomPolynomial(order_blinding_O)
	s.bp[id_Bz] = getRandomPolynomial(order_blinding_Z)
}

func (s *instance) initBSB22Commitments() (commitmentInfo constraint.PlonkCommitments, commitmentVal []fr.Element, cCommitments []*iop.Polynomial) {
	commitmentInfo = s.spr.CommitmentInfo.(constraint.PlonkCommitments)
	commitmentVal = make([]fr.Element, len(commitmentInfo)) // TODO @Tabaie get rid of this
	cCommitments = make([]*iop.Polynomial, len(commitmentInfo))
	s.proof.Bsb22Commitments = make([]kzg.Digest, len(commitmentInfo))

	// override the hint for the commitment constraints
	for i := range commitmentInfo {
		s.opt.SolverOpts = append(s.opt.SolverOpts,
			solver.OverrideHint(commitmentInfo[i].HintID, bsb22ComputeCommitmentHint(s.spr, s.pk, s.proof, cCommitments, &commitmentVal[i], i)))
	}

	return
}

func (s *instance) setupGKRHints() {
	if s.spr.GkrInfo.Is() {
		var gkrData cs.GkrSolvingData
		s.opt.SolverOpts = append(s.opt.SolverOpts,
			solver.OverrideHint(s.spr.GkrInfo.SolveHintID, cs.GkrSolveHint(s.spr.GkrInfo, &gkrData)),
			solver.OverrideHint(s.spr.GkrInfo.ProveHintID, cs.GkrProveHint(s.spr.GkrInfo.HashName, &gkrData)))
	}
}

func (s *instance) solveConstraints(fullWitness witness.Witness) (l, r, o *iop.Polynomial, err error) {
	_solution, err := s.spr.Solve(fullWitness, s.opt.SolverOpts...)
	if err != nil {
		return
	}
	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	l = iop.NewPolynomial(&evaluationLDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}).
		ToCanonical(&s.pk.Domain[0]).
		ToRegular()

	r = iop.NewPolynomial(&evaluationRDomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}).
		ToCanonical(&s.pk.Domain[0]).
		ToRegular()

	o = iop.NewPolynomial(&evaluationODomainSmall, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}).
		ToCanonical(&s.pk.Domain[0]).
		ToRegular()

	return
}

func (s *instance) completeQk(vWitness []fr.Element, commitmentInfo constraint.PlonkCommitments, commitmentVal []fr.Element) (qk *iop.Polynomial) {
	qk = s.pk.trace.Qk.Clone().ToLagrange(&s.pk.Domain[0]).ToRegular()
	qkCoeffs := qk.Coefficients()
	copy(qkCoeffs, vWitness[:len(s.spr.Public)])

	for i := range commitmentInfo {
		qkCoeffs[s.spr.GetNbPublicVariables()+commitmentInfo[i].CommitmentIndex] = commitmentVal[i]
	}
	return
}

func (s *instance) commitToLRO(l, r, o *iop.Polynomial) error {
	var err0, err1, err2 error
	chCommit0 := make(chan struct{}, 1)
	chCommit1 := make(chan struct{}, 1)
	go func() {
		s.proof.LRO[0], err0 = s.commitToPolyAndBlinding(l, s.bp[id_Bl])
		close(chCommit0)
	}()
	go func() {
		s.proof.LRO[1], err1 = s.commitToPolyAndBlinding(r, s.bp[id_Br])
		close(chCommit1)
	}()
	if s.proof.LRO[2], err2 = s.commitToPolyAndBlinding(o, s.bp[id_Bo]); err2 != nil {
		return err2
	}
	<-chCommit0
	<-chCommit1

	if err0 != nil {
		return err0
	}

	return err1
}

// deriveGammaAndBeta (copy constraint)
func (s *instance) deriveGammaAndBeta(wWitness []fr.Element) (gamma, beta fr.Element, err error) {
	if err = bindPublicData(s.fs, "gamma", s.pk.Vk, wWitness[:len(s.spr.Public)]); err != nil {
		return
	}
	gamma, err = deriveRandomness(s.fs, "gamma", &s.proof.LRO[0], &s.proof.LRO[1], &s.proof.LRO[2])
	if err != nil {
		return
	}

	bbeta, err := s.fs.ComputeChallenge("beta")
	if err != nil {
		return
	}

	beta.SetBytes(bbeta)
	return
}

// commitToZ commits to the blinded version of z
func (s *instance) commitToZ(z *iop.Polynomial) (err error) {
	s.proof.Z, err = s.commitToPolyAndBlinding(z, s.bp[id_Bz])
	return
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

func (s *instance) deriveAlpha(wWitness []fr.Element) (alpha fr.Element, err error) {
	alphaDeps := make([]*curve.G1Affine, len(s.proof.Bsb22Commitments)+1)
	for i := range s.proof.Bsb22Commitments {
		alphaDeps[i] = &s.proof.Bsb22Commitments[i]
	}
	alphaDeps[len(alphaDeps)-1] = &s.proof.Z
	alpha, err = deriveRandomness(s.fs, "alpha", alphaDeps...)
	return
}

func (s *instance) deriveZeta() (zeta fr.Element, err error) {
	zeta, err = deriveRandomness(s.fs, "zeta", &s.proof.H[0], &s.proof.H[1], &s.proof.H[2])
	return
}

// evaluateConstraints computes H
func (s *instance) evaluateConstraints(x []*iop.Polynomial, commitmentInfo constraint.PlonkCommitments, cCommitments []*iop.Polynomial, alpha, beta, gamma fr.Element) (h *iop.Polynomial, err error) {
	n := s.pk.Domain[0].Cardinality
	// TODO complete waste of memory find another way to do that
	identity := make([]fr.Element, n)
	identity[1].Set(&beta)

	lone := make([]fr.Element, n)
	lone[0].SetOne()

	x[id_Ql] = s.pk.trace.Ql
	x[id_Qr] = s.pk.trace.Qr
	x[id_Qm] = s.pk.trace.Qm
	x[id_Qo] = s.pk.trace.Qo
	// x[id_Qk] = qkCompleted
	x[id_ZS] = x[id_Z].ShallowClone().Shift(1)
	x[id_S1] = s.pk.trace.S1
	x[id_S2] = s.pk.trace.S2
	x[id_S3] = s.pk.trace.S3
	x[id_ID] = iop.NewPolynomial(&identity, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	x[id_LOne] = iop.NewPolynomial(&lone, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	for i := 0; i < len(commitmentInfo); i++ {
		x[id_Qci+2*i] = s.pk.trace.Qcp[i]
		x[id_Qci+2*i+1] = cCommitments[i]
	}

	numerator, err := computeNumerator(s.pk, x, s.bp, alpha, beta, gamma)
	if err != nil {
		return nil, err
	}

	h, err = divideByXMinusOne(numerator, [2]*fft.Domain{&s.pk.Domain[0], &s.pk.Domain[1]})
	return
}

// open Z (blinded) at ωζ
func (s *instance) openZ(z *iop.Polynomial, zeta fr.Element) (blindedZ []fr.Element, err error) {
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &s.pk.Vk.Generator)
	blindedZ = getBlindedCoefficients(z, s.bp[id_Bz])
	// open z at zeta
	s.proof.ZShiftedOpening, err = kzg.Open(blindedZ, zetaShifted, s.pk.Kzg)
	return
}

func (s *instance) commitToH(h1, h2, h3 []fr.Element) error {
	return commitToQuotient(h1, h2, h3, s.proof, s.pk.Kzg)
}

// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
func (s *instance) foldH(h1, h2, h3 []fr.Element, zeta fr.Element) (foldedH []fr.Element, digest kzg.Digest) {
	var n big.Int
	n.SetUint64(s.pk.Domain[0].Cardinality + 2)

	var zetaPowerNplusTwo fr.Element
	zetaPowerNplusTwo.Exp(zeta, &n)
	zetaPowerNplusTwo.BigInt(&n)

	digest.ScalarMultiplication(&s.proof.H[2], &n)
	digest.Add(&digest, &s.proof.H[1])       // ζᵐ⁺²*Comm(h3)
	digest.ScalarMultiplication(&digest, &n) // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2)
	digest.Add(&digest, &s.proof.H[0])

	// fold H (H₀ + ζᵐ⁺²*H₁ + ζ²⁽ᵐ⁺²⁾H₂))
	foldedH = h3

	for i := 0; i < int(s.pk.Domain[0].Cardinality)+2; i++ {
		foldedH[i].
			Mul(&foldedH[i], &zetaPowerNplusTwo).
			Add(&foldedH[i], &h2[i]).
			Mul(&foldedH[i], &zetaPowerNplusTwo).
			Add(&foldedH[i], &h1[i])
	}

	return
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

	// get the []fr.Element representation of the witness
	wWitness, ok := fullWitness.Vector().(fr.Vector)
	if !ok {
		return nil, witness.ErrInvalidWitness
	}

	start := time.Now()

	// create a transcript manager to apply Fiat Shamir
	hFunc := sha256.New()
	fs := fiatshamir.NewTranscript(hFunc, "gamma", "beta", "alpha", "zeta")

	// result
	proof := &Proof{}

	// init instance
	instance := instance{
		pk:    pk,
		proof: proof,
		spr:   spr,
		opt:   &opt,
		bp:    make([]*iop.Polynomial, nb_blinding_polynomials),
		fs:    &fs,
	}

	// init BSB22 commitments
	commitmentInfo, commitmentVal, cCommitments := instance.initBSB22Commitments()

	// override the hint for GKR constraints
	instance.setupGKRHints()

	// x stores tracks the polynomial we need
	x := make([]*iop.Polynomial, id_Qci+2*len(commitmentInfo))

	// solve constraints
	// l, r, o are returned in canonical regular form, not blinded.
	x[id_L], x[id_R], x[id_O], err = instance.solveConstraints(fullWitness)
	if err != nil {
		return nil, err
	}

	// complete qk
	x[id_Qk] = instance.completeQk(wWitness, commitmentInfo, commitmentVal)

	// init blinding polynomials
	instance.initBlindingPolynomials()

	// commit to l, r, o and add blinding factors
	if err := instance.commitToLRO(x[id_L], x[id_R], x[id_O]); err != nil {
		return nil, err
	}

	// derive gamma, beta (copy constraint)
	gamma, beta, err := instance.deriveGammaAndBeta(wWitness)
	if err != nil {
		return nil, err
	}

	// compute accumulating ratio for the copy constraint
	x[id_Z], err = iop.BuildRatioCopyConstraint(
		[]*iop.Polynomial{
			x[id_L],
			x[id_R],
			x[id_O],
		},
		pk.trace.S,
		beta,
		gamma,
		iop.Form{Basis: iop.Canonical, Layout: iop.Regular},
		&pk.Domain[0],
	)
	if err != nil {
		return nil, err
	}

	// commit to the blinded version of z
	if err := instance.commitToZ(x[id_Z]); err != nil {
		return nil, err
	}

	// derive alpha
	alpha, err := instance.deriveAlpha(wWitness)
	if err != nil {
		return nil, err
	}

	// compute h
	h, err := instance.evaluateConstraints(x, commitmentInfo, cCommitments, alpha, beta, gamma)
	if err != nil {
		return nil, err
	}

	// compute kzg commitments of h2, h2 and h3 (proof.H[0], proof.H[1], proof.H[2])
	h1 := h.Coefficients()[:pk.Domain[0].Cardinality+2]
	h2 := h.Coefficients()[pk.Domain[0].Cardinality+2 : 2*(pk.Domain[0].Cardinality+2)]
	h3 := h.Coefficients()[2*(pk.Domain[0].Cardinality+2) : 3*(pk.Domain[0].Cardinality+2)]

	if err := instance.commitToH(h1, h2, h3); err != nil {
		return nil, err
	}

	// derive zeta
	zeta, err := instance.deriveZeta()
	if err != nil {
		return nil, err
	}

	// open Z (blinded) at ωζ (proof.ZShiftedOpening)
	blindedZ, err := instance.openZ(x[id_Z], zeta)
	if err != nil {
		return nil, err
	}

	// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
	foldedH, foldedHDigest := instance.foldH(h1, h2, h3, zeta)

	// linearised polynomial
	qcpzeta := make([]fr.Element, len(commitmentInfo))
	blzeta := evaluateBlinded(x[id_L], instance.bp[id_Bl], zeta) // x[id_L].ToRegular().Evaluate(zeta)
	brzeta := evaluateBlinded(x[id_R], instance.bp[id_Br], zeta) // x[id_R].ToRegular().Evaluate(zeta)
	bozeta := evaluateBlinded(x[id_O], instance.bp[id_Bo], zeta) // x[id_O].ToRegular().Evaluate(zeta)
	for i := 0; i < len(commitmentInfo); i++ {
		qcpzeta[i] = pk.trace.Qcp[i].ToRegular().Evaluate(zeta)
	}
	bzuzeta := proof.ZShiftedOpening.ClaimedValue

	linearizedPolynomialCanonical := computeLinearizedPolynomial(
		blzeta,
		brzeta,
		bozeta,
		alpha,
		beta,
		gamma,
		zeta,
		bzuzeta,
		qcpzeta,
		blindedZ,
		coefficients(cCommitments),
		pk,
	)

	linearizedPolynomialDigest, err := kzg.Commit(linearizedPolynomialCanonical, pk.Kzg, runtime.NumCPU()*2)
	if err != nil {
		return nil, err
	}

	// Batch opening
	polysQcp := coefficients(pk.trace.Qcp)
	polysToOpen := make([][]fr.Element, 7+len(polysQcp))
	copy(polysToOpen[7:], polysQcp)
	polysToOpen[0] = foldedH
	polysToOpen[1] = linearizedPolynomialCanonical
	polysToOpen[2] = getBlindedCoefficients(x[id_L], instance.bp[id_Bl])
	polysToOpen[3] = getBlindedCoefficients(x[id_R], instance.bp[id_Br])
	polysToOpen[4] = getBlindedCoefficients(x[id_O], instance.bp[id_Bo])
	polysToOpen[5] = x[id_S1].Coefficients()
	polysToOpen[6] = x[id_S2].Coefficients()

	digestsToOpen := make([]curve.G1Affine, len(pk.Vk.Qcp)+7)
	copy(digestsToOpen[7:], pk.Vk.Qcp)
	digestsToOpen[0] = foldedHDigest
	digestsToOpen[1] = linearizedPolynomialDigest
	digestsToOpen[2] = proof.LRO[0]
	digestsToOpen[3] = proof.LRO[1]
	digestsToOpen[4] = proof.LRO[2]
	digestsToOpen[5] = pk.Vk.S[0]
	digestsToOpen[6] = pk.Vk.S[1]

	proof.BatchedProof, err = kzg.BatchOpenSinglePoint(
		polysToOpen,
		digestsToOpen,
		zeta,
		hFunc,
		pk.Kzg,
	)
	if err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	return proof, nil
}

// evaluate the full set of constraints, all polynomials in x are back in
// canonical regular form at the end
func computeNumerator(pk *ProvingKey, x []*iop.Polynomial, bp []*iop.Polynomial, alpha, beta, gamma fr.Element) (*iop.Polynomial, error) {

	scale(x[id_S1], beta)
	scale(x[id_S2], beta)
	scale(x[id_S3], beta)

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

		a.Add(&u[id_S1], &u[id_L]).Add(&a, &gamma)
		b.Add(&u[id_S2], &u[id_R]).Add(&b, &gamma)
		c.Add(&u[id_S3], &u[id_O]).Add(&c, &gamma)
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
	for i := 0; i < rho; i++ {

		// shift polynomials to be in the correct coset
		toCanonicalRegular(x, &pk.Domain[0]) // TODO no need to put in regular form
		batchScalePowers(x, shifters[i])     // TODO take in account the layout in batchScalePowers

		// fft in the correct coset
		toLagrange(x, &pk.Domain[0])

		// blind l, r, o, z
		batchScalePowers(bp, shifters[i])
		coset.Mul(&coset, &shifters[i])
		tmp.Exp(coset, bn).Sub(&tmp, &one)
		batchScale(bp, tmp) // bl <- bl *( (s*ωⁱ)ⁿ-1 )s
		batchBlind(x[id_L:id_Z+1], bp, pk.Domain[0].Generator)

		// TODO modify Evaluate so it takes a buffer to store the result insted of allocating a new polynomial
		buf, err := iop.Evaluate(
			allConstraints,
			iop.Form{Basis: iop.Lagrange, Layout: iop.Regular},
			x...,
		)
		if err != nil {
			return nil, err
		}
		for j := 0; j < int(pk.Domain[0].Cardinality); j++ {
			t := buf.GetCoeff(j)
			cres[rho*j+i].Set(&t)
		}

		// unblind l, r, o, z
		batchUnblind(x[id_L:id_Z+1], bp, pk.Domain[0].Generator)
		tmp.Inverse(&tmp)
		batchScale(bp, tmp) // bl <- bl *( (s*ωⁱ)ⁿ-1 )s

	}

	// scale everything back
	toCanonicalRegular(x, &pk.Domain[0])
	beta.Inverse(&beta)
	scale(x[id_S1], beta)
	scale(x[id_S2], beta)
	scale(x[id_S3], beta)
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

func batchUnblind(p, b []*iop.Polynomial, w fr.Element) {
	for i := 0; i < len(p); i++ {
		unblind(p[i], b[i], w)
	}
}

// computes p - b on <\omega>
func unblind(p, b *iop.Polynomial, w fr.Element) {
	cp := p.Coefficients()
	var x, y fr.Element
	x.SetOne()
	n := p.Size()
	// TODO add a method SetCoeff in gnark-crypto
	if p.Layout == iop.Regular {
		for i := 0; i < p.Size(); i++ {
			y = b.Evaluate(x)
			cp[i].Sub(&cp[i], &y)
			x.Mul(&x, &w)
		}
	} else {
		nn := uint64(64 - bits.TrailingZeros(uint(n)))
		for i := 0; i < p.Size(); i++ {
			y = b.Evaluate(x)
			iRev := bits.Reverse64(uint64(i)) >> nn
			cp[iRev].Sub(&cp[iRev], &y)
			x.Mul(&x, &w)
		}
	}
}

func batchBlind(p, b []*iop.Polynomial, w fr.Element) {
	for i := 0; i < len(p); i++ {
		blind(p[i], b[i], w)
	}
}

// computes p + b on <\omega>
func blind(p, b *iop.Polynomial, w fr.Element) {
	cp := p.Coefficients()
	var x, y fr.Element
	x.SetOne()
	n := p.Size()
	// TODO add a method SetCoeff in gnark-crypto
	if p.Layout == iop.Regular {
		for i := 0; i < p.Size(); i++ {
			y = b.Evaluate(x)
			cp[i].Add(&cp[i], &y)
			x.Mul(&x, &w)
		}
	} else {
		nn := uint64(64 - bits.TrailingZeros(uint(n)))
		for i := 0; i < p.Size(); i++ {
			y = b.Evaluate(x)
			iRev := bits.Reverse64(uint64(i)) >> nn
			cp[iRev].Add(&cp[iRev], &y)
			x.Mul(&x, &w)
		}
	}
}

func toLagrange(x []*iop.Polynomial, d *fft.Domain) {
	for i := 0; i < len(x); i++ {
		x[i].ToLagrange(d)
	}
}

func toCanonicalRegular(x []*iop.Polynomial, d *fft.Domain) {
	for i := 0; i < len(x); i++ {
		x[i].ToCanonical(d).ToRegular()
	}
}
func batchScalePowers(p []*iop.Polynomial, w fr.Element) {
	for i := 0; i < len(p); i++ {
		if i == id_ZS { // the scaling has already been done on id_Z, which points to the same coeff array
			continue
		}
		scalePowers(p[i], w)
	}
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

func batchScale(p []*iop.Polynomial, w fr.Element) {
	for i := 0; i < len(p); i++ {
		scale(p[i], w)
	}
}

func scale(p *iop.Polynomial, w fr.Element) {
	cp := p.Coefficients()
	for i := 0; i < p.Size(); i++ {
		cp[i].Mul(&cp[i], &w)
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
	n := runtime.NumCPU()
	var err0, err1, err2 error
	chCommit0 := make(chan struct{}, 1)
	chCommit1 := make(chan struct{}, 1)
	go func() {
		proof.H[0], err0 = kzg.Commit(h1, kzgPk, n)
		close(chCommit0)
	}()
	go func() {
		proof.H[1], err1 = kzg.Commit(h2, kzgPk, n)
		close(chCommit1)
	}()
	if proof.H[2], err2 = kzg.Commit(h3, kzgPk, n); err2 != nil {
		return err2
	}
	<-chCommit0
	<-chCommit1

	if err0 != nil {
		return err0
	}

	return err1
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
