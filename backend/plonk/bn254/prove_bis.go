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
	"time"

	"github.com/consensys/gnark/backend/witness"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/logger"
)

// TODO in gnark-crypto:
// * remove everything linked to the blinding
// * add SetCoeff method
// * modify GetCoeff -> if the poly is shifted and in canonical form the index is computed differently

func printPoly(p *iop.Polynomial) {
	cc := p.Coefficients()
	fmt.Printf("[")
	for i := 0; i < len(cc); i++ {
		fmt.Println(cc[i].String())
	}
	fmt.Println("]")
}

func prettyPrint(name string, p *iop.Polynomial, d *fft.Domain) {
	c := p.Clone()
	c.ToCanonical(d).ToRegular()
	cc := c.Coefficients()
	fmt.Printf("%s = ", name)
	for i := 0; i < len(cc); i++ {
		fmt.Printf("%s*x**%d", cc[i].String(), i)
		if i < len(cc)-1 {
			fmt.Printf("+")
		}
	}
	fmt.Println("")
}

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
	order_blinding_Z = -1
)

func ProveBis(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {

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

	// pick a hash function that will be used to derive the challenges
	hFunc := sha256.New()

	// create a transcript manager to apply Fiat Shamir
	fs := fiatshamir.NewTranscript(hFunc, "gamma", "beta", "alpha", "zeta")

	// result
	proof := &Proof{}

	commitmentInfo := spr.CommitmentInfo.(constraint.PlonkCommitments)
	commitmentVal := make([]fr.Element, len(commitmentInfo)) // TODO @Tabaie get rid of this
	cCommitments := make([]*iop.Polynomial, len(commitmentInfo))
	proof.Bsb22Commitments = make([]kzg.Digest, len(commitmentInfo))

	// override the hint for the commitment constraints
	for i := range commitmentInfo {
		opt.SolverOpts = append(opt.SolverOpts,
			solver.OverrideHint(commitmentInfo[i].HintID, bsb22ComputeCommitmentHint(spr, pk, proof, cCommitments, &commitmentVal[i], i)))
	}

	// override the hint for GKR constraints
	if spr.GkrInfo.Is() {
		var gkrData cs.GkrSolvingData
		opt.SolverOpts = append(opt.SolverOpts,
			solver.OverrideHint(spr.GkrInfo.SolveHintID, cs.GkrSolveHint(spr.GkrInfo, &gkrData)),
			solver.OverrideHint(spr.GkrInfo.ProveHintID, cs.GkrProveHint(spr.GkrInfo.HashName, &gkrData)))
	}

	// query l, r, o in Lagrange basis, not blinded
	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
	_solution, err := spr.Solve(fullWitness, opt.SolverOpts...)
	if err != nil {
		return nil, err
	}

	x := make([]*iop.Polynomial, id_Qci+2*len(commitmentInfo))

	solution := _solution.(*cs.SparseR1CSSolution)
	evaluationLDomainSmall := []fr.Element(solution.L)
	evaluationRDomainSmall := []fr.Element(solution.R)
	evaluationODomainSmall := []fr.Element(solution.O)
	x[id_L] = iop.NewPolynomial(&evaluationLDomainSmall, lagReg)
	x[id_R] = iop.NewPolynomial(&evaluationRDomainSmall, lagReg)
	x[id_O] = iop.NewPolynomial(&evaluationODomainSmall, lagReg)

	// complete qk
	fw, ok := fullWitness.Vector().(fr.Vector)
	if !ok {
		return nil, witness.ErrInvalidWitness
	}
	qkCompleted := pk.trace.Qk.Clone().ToLagrange(&pk.Domain[0]).ToRegular()
	qkCompletedCoeffs := qkCompleted.Coefficients()
	copy(qkCompletedCoeffs, fw[:len(spr.Public)])
	for i := range commitmentInfo {
		qkCompletedCoeffs[spr.GetNbPublicVariables()+commitmentInfo[i].CommitmentIndex] = commitmentVal[i]
	}

	// blinding of l, r, o
	x[id_L].ToCanonical(&pk.Domain[0]).ToRegular()
	x[id_R].ToCanonical(&pk.Domain[0]).ToRegular()
	x[id_O].ToCanonical(&pk.Domain[0]).ToRegular()
	if err := commitToLRONotBlinded(x[id_L], x[id_R], x[id_O], proof, pk.Kzg); err != nil {
		return nil, err
	}
	bp := make([]*iop.Polynomial, nb_blinding_polynomials)
	bp[id_Bl] = getRandomPolynomial(order_blinding_L)
	bp[id_Br] = getRandomPolynomial(order_blinding_R)
	bp[id_Bo] = getRandomPolynomial(order_blinding_O)
	cbl := commitBlindingFactor(int(pk.Domain[0].Cardinality), bp[id_Bl], pk.Kzg)
	cbr := commitBlindingFactor(int(pk.Domain[0].Cardinality), bp[id_Br], pk.Kzg)
	cbo := commitBlindingFactor(int(pk.Domain[0].Cardinality), bp[id_Bo], pk.Kzg)
	proof.LRO[0].Add(&cbl, &proof.LRO[0])
	proof.LRO[1].Add(&cbr, &proof.LRO[1])
	proof.LRO[2].Add(&cbo, &proof.LRO[2])

	// derive gamma (copy constraint)
	if err := bindPublicData(&fs, "gamma", pk.Vk, fw[:len(spr.Public)]); err != nil {
		return nil, err
	}
	gamma, err := deriveRandomness(&fs, "gamma", &proof.LRO[0], &proof.LRO[1], &proof.LRO[2])
	if err != nil {
		return nil, err
	}

	// derive beta (copy constraint)
	bbeta, err := fs.ComputeChallenge("beta")
	if err != nil {
		return nil, err
	}
	var beta fr.Element
	beta.SetBytes(bbeta)

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
		return proof, err
	}

	// commit to the blinded version of z
	proof.Z, err = kzg.Commit(x[id_Z].Coefficients(), pk.Kzg)
	if err != nil {
		return proof, err
	}
	bp[id_Bz] = getRandomPolynomial(order_blinding_Z)
	cbz := commitBlindingFactor(int(pk.Domain[0].Cardinality), bp[id_Bz], pk.Kzg)
	proof.Z.Add(&cbz, &proof.Z)

	// TODO complete waste of memory find another way to do that
	identity := make([]fr.Element, pk.Domain[0].Cardinality)
	identity[1].Set(&beta)
	pidentity := iop.NewPolynomial(&identity, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})

	lone := make([]fr.Element, pk.Domain[0].Cardinality)
	lone[0].SetOne()

	x[id_Ql] = pk.trace.Ql
	x[id_Qr] = pk.trace.Qr
	x[id_Qm] = pk.trace.Qm
	x[id_Qo] = pk.trace.Qo
	x[id_Qk] = qkCompleted
	x[id_ZS] = x[id_Z].ShallowClone().Shift(1)
	x[id_S1] = pk.trace.S1
	x[id_S2] = pk.trace.S2
	x[id_S3] = pk.trace.S3
	x[id_ID] = pidentity
	x[id_LOne] = iop.NewPolynomial(&lone, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	for i := 0; i < len(commitmentInfo); i++ {
		x[id_Qci+2*i] = pk.trace.Qcp[i]
		x[id_Qci+2*i+1] = cCommitments[i]
	}
	// prettyPrint("cl", x[id_L], &pk.Domain[0])
	// prettyPrint("cr", x[id_R], &pk.Domain[0])
	// prettyPrint("co", x[id_O], &pk.Domain[0])
	// prettyPrint("ql", x[id_Ql], &pk.Domain[0])
	// prettyPrint("qr", x[id_Qr], &pk.Domain[0])
	// prettyPrint("qm", x[id_Qm], &pk.Domain[0])
	// prettyPrint("qo", x[id_Qo], &pk.Domain[0])
	// prettyPrint("qk", x[id_Qk], &pk.Domain[0])
	// prettyPrint("bl", bp[id_Bl], &pk.Domain[0])

	var alpha fr.Element
	alphaDeps := make([]*curve.G1Affine, len(proof.Bsb22Commitments)+1)
	for i := range proof.Bsb22Commitments {
		alphaDeps[i] = &proof.Bsb22Commitments[i]
	}
	alphaDeps[len(alphaDeps)-1] = &proof.Z
	alpha, err = deriveRandomness(&fs, "alpha", alphaDeps...)
	if err != nil {
		return proof, err
	}

	constraintsEvaluation, err := computeNumerator(*pk, x, bp, alpha, beta, gamma)
	if err != nil {
		return proof, err
	}
	// printPoly(constraintsEvaluation)

	h, err := divideByXMinusOne(constraintsEvaluation, [2]*fft.Domain{&pk.Domain[0], &pk.Domain[1]})
	if err != nil {
		return nil, err
	}
	printPoly(h)

	// compute kzg commitments of h1, h2 and h3
	if err := commitToQuotient(
		h.Coefficients()[:pk.Domain[0].Cardinality+2],
		h.Coefficients()[pk.Domain[0].Cardinality+2:2*(pk.Domain[0].Cardinality+2)],
		h.Coefficients()[2*(pk.Domain[0].Cardinality+2):3*(pk.Domain[0].Cardinality+2)],
		proof, pk.Kzg); err != nil {
		return nil, err
	}

	// derive zeta
	zeta, err := deriveRandomness(&fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	// open Z (blinded) at ωζ
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &pk.Vk.Generator)
	blindedZCoeffs := getBlindedCoefficients(x[id_Z], bp[id_Bz])
	proof.ZShiftedOpening, err = kzg.Open(
		blindedZCoeffs,
		zetaShifted,
		pk.Kzg,
	)
	if err != nil {
		return nil, err
	}

	// fold the commitment to H ([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾[H₂])
	var foldedHDigest kzg.Digest
	var bSize big.Int
	var zetaPowerNplusTwo fr.Element
	bSize.SetUint64(pk.Domain[0].Cardinality + 2)
	zetaPowerNplusTwo.Exp(zeta, &bSize)
	var bzetaPowerNplusTwo big.Int
	zetaPowerNplusTwo.BigInt(&bzetaPowerNplusTwo)
	foldedHDigest = proof.H[2]
	foldedHDigest.ScalarMultiplication(&foldedHDigest, &bzetaPowerNplusTwo)
	foldedHDigest.Add(&foldedHDigest, &proof.H[1])                          // ζᵐ⁺²*Comm(h3)
	foldedHDigest.ScalarMultiplication(&foldedHDigest, &bzetaPowerNplusTwo) // ζ²⁽ᵐ⁺²⁾*Comm(h3) + ζᵐ⁺²*Comm(h2)
	foldedHDigest.Add(&foldedHDigest, &proof.H[0])

	// fold H (H₀ + ζᵐ⁺²*H₁ + ζ²⁽ᵐ⁺²⁾H₂))
	foldedH := h.Coefficients()[2*(pk.Domain[0].Cardinality+2) : 3*(pk.Domain[0].Cardinality+2)]
	h1 := h.Coefficients()[pk.Domain[0].Cardinality+2 : 2*(pk.Domain[0].Cardinality+2)]
	h2 := h.Coefficients()[:pk.Domain[0].Cardinality+2]
	for i := 0; i < int(pk.Domain[0].Cardinality)+2; i++ {
		foldedH[i].
			Mul(&foldedH[i], &zetaPowerNplusTwo).
			Add(&foldedH[i], &h1[i]).
			Mul(&foldedH[i], &zetaPowerNplusTwo).
			Add(&foldedH[i], &h2[i])
	}

	// linearised polynomial
	// var linearizedPolynomialCanonical []fr.Element
	// var linearizedPolynomialDigest curve.G1Affine
	qcpzeta := make([]fr.Element, len(commitmentInfo))
	blzeta := evaluateBlinded(x[id_L], bp[id_Bl], zeta) // x[id_L].ToRegular().Evaluate(zeta)
	brzeta := evaluateBlinded(x[id_R], bp[id_Br], zeta) // x[id_R].ToRegular().Evaluate(zeta)
	bozeta := evaluateBlinded(x[id_O], bp[id_Bo], zeta) // x[id_O].ToRegular().Evaluate(zeta)
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
		blindedZCoeffs,
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
	polysToOpen[2] = getBlindedCoefficients(x[id_L], bp[id_Bl])
	polysToOpen[3] = getBlindedCoefficients(x[id_R], bp[id_Br])
	polysToOpen[4] = getBlindedCoefficients(x[id_O], bp[id_Bo])
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
func computeNumerator(pk ProvingKey, x []*iop.Polynomial, bp []*iop.Polynomial, alpha, beta, gamma fr.Element) (*iop.Polynomial, error) {

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
		batchBlind(x[id_L:id_Z], bp, pk.Domain[0].Generator)

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
		batchUnblind(x[id_L:id_Z], bp, pk.Domain[0].Generator)
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

	coeffsP := b.Coefficients()
	sizeP := b.Size()

	// lo
	var tmp curve.G1Affine
	points := make([]curve.G1Affine, sizeP)
	copy(points, key.G1[:sizeP])
	tmp.MultiExp(points, coeffsP, ecc.MultiExpConfig{})

	// hi
	copy(points, key.G1[n:n+sizeP])
	var res curve.G1Affine
	res.MultiExp(points, coeffsP, ecc.MultiExpConfig{})
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

// fills proof.LRO with kzg commits of bcl, bcr and bco
func commitToLRONotBlinded(l, r, o *iop.Polynomial, proof *Proof, kzgPk kzg.ProvingKey) error {

	cl := l.Coefficients()
	cr := r.Coefficients()
	co := o.Coefficients()

	n := runtime.NumCPU()
	var err0, err1, err2 error
	chCommit0 := make(chan struct{}, 1)
	chCommit1 := make(chan struct{}, 1)
	go func() {
		proof.LRO[0], err0 = kzg.Commit(cl, kzgPk, n)
		close(chCommit0)
	}()
	go func() {
		proof.LRO[1], err1 = kzg.Commit(cr, kzgPk, n)
		close(chCommit1)
	}()
	if proof.LRO[2], err2 = kzg.Commit(co, kzgPk, n); err2 != nil {
		return err2
	}
	<-chCommit0
	<-chCommit1

	if err0 != nil {
		return err0
	}

	return err1
}
