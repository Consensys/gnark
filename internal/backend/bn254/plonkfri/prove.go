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

package plonkfri

import (
	"math/big"
	"math/bits"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
	"github.com/consensys/gnark/internal/utils"
)

type Proof struct {

	// commitments to the solution vectors
	LRO [3]Commitment

	// commitment to Z (permutation polynomial)
	Z Commitment

	// commitment to h1,h2,h3 such that h = h1 + X**n*h2 + X**2nh3 the quotient polynomial
	H [3]Commitment

	// opening proofs for L, R, O
	OpeningsLRO [3]OpeningProof

	// opening proofs for Z, Zu
	OpeningsZ [2]OpeningProof

	// opening proof for H
	OpeningsH [3]OpeningProof

	// opening proofs for ql, qr, qm, qo, qk
	OpeningsQlQrQmQoQk [5]OpeningProof
}

func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness bn254witness.Witness, opt backend.ProverConfig) (*Proof, error) {

	var proof Proof

	// 1 - solve the system
	var solution []fr.Element
	var err error
	if solution, err = spr.Solve(fullWitness, opt); err != nil {
		if !opt.Force {
			return nil, err
		} else {
			// we need to fill solution with random values
			var r fr.Element
			_, _ = r.SetRandom()
			for i := spr.NbPublicVariables + spr.NbSecretVariables; i < len(solution); i++ {
				solution[i] = r
				r.Double(&r)
			}
		}
	}

	ll, lr, lo := computeLRO(spr, pk, solution)

	bcl, bcr, bco, err := computeBlindedLRO(ll, lr, lo, &pk.DomainSmall)
	if err != nil {
		return nil, err
	}

	// 2 - commit to lro
	proof.LRO[0] = pk.Cscheme.Commit(bcl)
	proof.LRO[1] = pk.Cscheme.Commit(bcr)
	proof.LRO[2] = pk.Cscheme.Commit(bco)

	// 3 - compute Z
	var beta, gamma fr.Element
	beta.SetUint64(9)
	gamma.SetUint64(10)
	bz, err := computeBlindedZ(ll, lr, lo, pk, beta, gamma)
	if err != nil {
		return nil, err
	}

	// 4 - commit to Z
	proof.Z = pk.Cscheme.Commit(bz)

	// 5 - compute H
	var alpha fr.Element
	alpha.SetUint64(11)

	lsQk := make([]fr.Element, pk.DomainBig.Cardinality)
	copy(lsQk, fullWitness[:spr.NbPublicVariables])
	copy(lsQk[spr.NbPublicVariables:], pk.LQkIncomplete[spr.NbPublicVariables:])
	pk.DomainSmall.FFTInverse(lsQk[:pk.DomainSmall.Cardinality], fft.DIF, 0)
	fft.BitReverse(lsQk[:pk.DomainSmall.Cardinality])

	lsQk = fftBigCosetWOBitReverse(lsQk, &pk.DomainBig)

	var lsBl, lsBr, lsBo, lsBz []fr.Element
	lsBl = fftBigCosetWOBitReverse(bcl, &pk.DomainBig)
	lsBr = fftBigCosetWOBitReverse(bcr, &pk.DomainBig)
	lsBo = fftBigCosetWOBitReverse(bco, &pk.DomainBig)

	constraintsInd := evalConstraintsWOBitReverse(pk, lsBl, lsBr, lsBo, lsQk) // CORRECT

	lsBz = fftBigCosetWOBitReverse(bz, &pk.DomainBig) // CORRECT

	constraintsOrdering := evalConstraintOrdering(pk, lsBz, lsBl, lsBr, lsBo, beta, gamma) // CORRECT

	h1, h2, h3 := computeH(pk, constraintsInd, constraintsOrdering, lsBz, alpha) // CORRECT

	// 6 - commit to H
	proof.H[0] = pk.Cscheme.Commit(h1)
	proof.H[1] = pk.Cscheme.Commit(h2)
	proof.H[2] = pk.Cscheme.Commit(h3) // CORRECT

	// 7 - build the opening proofs
	var zeta fr.Element
	zeta.SetUint64(12)

	proof.OpeningsH[0] = pk.Cscheme.Open(proof.H[0], zeta)
	proof.OpeningsH[1] = pk.Cscheme.Open(proof.H[1], zeta)
	proof.OpeningsH[2] = pk.Cscheme.Open(proof.H[2], zeta)

	proof.OpeningsLRO[0] = pk.Cscheme.Open(bcl, zeta)
	proof.OpeningsLRO[1] = pk.Cscheme.Open(bcr, zeta)
	proof.OpeningsLRO[2] = pk.Cscheme.Open(bco, zeta)

	proof.OpeningsQlQrQmQoQk[0] = pk.Cscheme.Open(pk.CQl, zeta)
	proof.OpeningsQlQrQmQoQk[1] = pk.Cscheme.Open(pk.CQr, zeta)
	proof.OpeningsQlQrQmQoQk[2] = pk.Cscheme.Open(pk.CQm, zeta)
	proof.OpeningsQlQrQmQoQk[3] = pk.Cscheme.Open(pk.CQo, zeta)
	proof.OpeningsQlQrQmQoQk[4] = pk.Cscheme.Open(pk.CQkIncomplete, zeta)

	return &proof, nil
}

// evalConstraintOrdering computes the evaluation of Z(uX)g1g2g3-Z(X)f1f2f3 on the odd
// cosets of (Z/8mZ)/(Z/mZ), where m=nbConstraints+nbAssertions.
//
// * LsZ evaluation of the blinded permutation accumulator polynomial on odd cosets (bit reversed)
// * lsL, lsR, lsO evaluation of the blinded solution vectors on odd cosets (bit reversed)
// * gamma randomization
func evalConstraintOrdering(pk *ProvingKey, lsZ, lsL, lsR, lsO []fr.Element, beta, gamma fr.Element) []fr.Element {

	// computes Z(uX)g1g2g3l-Z(X)f1f2f3l on the odd cosets of (Z/8mZ)/(Z/4mZ)
	res := make([]fr.Element, pk.DomainBig.Cardinality) // re use allocated memory for LsS1

	// utils variables useful for using bit reversed indices
	s := len(lsZ)
	nn := uint64(64 - bits.TrailingZeros64(uint64(s)))

	// needed to shift LsZ
	toShift := int(pk.DomainBig.Cardinality / pk.DomainSmall.Cardinality)

	var one fr.Element
	one.SetOne()

	utils.Parallelize(int(pk.DomainBig.Cardinality), func(start, end int) {

		var f [3]fr.Element
		var g [3]fr.Element

		for i := start; i < end; i++ {

			// careful of bit reverse ordering
			irev := int(bits.Reverse64(uint64(i)) >> nn)
			//eID = evalID[irev]
			shiftedZ := bits.Reverse64(uint64((irev+toShift)%s)) >> nn

			f[0].Mul(&pk.LsId1[i], &beta).Add(&f[0], &lsL[i]).Add(&f[0], &gamma) //l_i+i*beta+gamma
			f[1].Mul(&pk.LsId2[i], &beta).Add(&f[1], &lsR[i]).Add(&f[1], &gamma) //r_i+(i+n)*beta+gamma
			f[2].Mul(&pk.LsId3[i], &beta).Add(&f[2], &lsO[i]).Add(&f[2], &gamma) //o_i+(i+2n)*beta+gamma

			g[0].Mul(&pk.LsS1[i], &beta).Add(&g[0], &lsL[i]).Add(&g[0], &gamma) //l_i+s1*beta+gamma
			g[1].Mul(&pk.LsS2[i], &beta).Add(&g[1], &lsR[i]).Add(&g[1], &gamma) //r_i+s2*beta+gamma
			g[2].Mul(&pk.LsS3[i], &beta).Add(&g[2], &lsO[i]).Add(&g[2], &gamma) //o_i+s3*beta+gamma

			f[0].Mul(&f[0], &f[1]).
				Mul(&f[0], &f[2]).
				Mul(&f[0], &lsZ[i]) // z_i*(l_i+i*beta+gamma)*(r_i+(i+n)*beta+gamma)*(o_i+(i+2n)*beta+gamma)

			g[0].Mul(&g[0], &g[1]).
				Mul(&g[0], &g[2]).
				Mul(&g[0], &lsZ[shiftedZ]) // u*z_i*(l_i+s1*beta+gamma)*(r_i+s2*beta+gamma)*(o_i+s3*beta+gamma)

			res[i].Sub(&g[0], &f[0])
		}
	})

	return res
}

// evalConstraintsWOBitReverse computes the evaluation of lL+qrR+qqmL.R+qoO+k on
// the odd coset of (Z/8mZ)/(Z/4mZ), where m=nbConstraints+nbAssertions.
//
// * lsL, lsR, lsO are the evaluation of the blinded solution vectors on odd cosets
// * lsQk is the completed version of qk, in canonical version
//
// lsL, lsR, lsO are in bit reversed order, lsQk is in the correct order.
func evalConstraintsWOBitReverse(pk *ProvingKey, lsL, lsR, lsO, lsQk []fr.Element) []fr.Element {

	res := make([]fr.Element, pk.DomainBig.Cardinality)
	// nn := uint64(64 - bits.TrailingZeros64(pk.DomainBig.Cardinality))

	utils.Parallelize(len(res), func(start, end int) {

		var t0, t1 fr.Element

		for i := start; i < end; i++ {

			// irev := bits.Reverse64(uint64(i)) >> nn

			t1.Mul(&pk.LsQm[i], &lsR[i]) // qm.r
			t1.Add(&t1, &pk.LsQl[i])     // qm.r + ql
			t1.Mul(&t1, &lsL[i])         //  qm.l.r + ql.l

			t0.Mul(&pk.LsQr[i], &lsR[i])
			t0.Add(&t0, &t1) // qm.l.r + ql.l + qr.r

			t1.Mul(&pk.LsQo[i], &lsO[i])
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
// Warning: result is in bit reversed order, we do a bit reverse operation only once in computeH
func fftBigCosetWOBitReverse(poly []fr.Element, domainBig *fft.Domain) []fr.Element {

	res := make([]fr.Element, domainBig.Cardinality)

	// we copy poly in res and scale by coset here
	// to avoid FFT scaling on domainBig.Cardinality (res is very sparse)
	utils.Parallelize(len(poly), func(start, end int) {
		for i := start; i < end; i++ {
			res[i].Mul(&poly[i], &domainBig.CosetTable[0][i])
		}
	}, runtime.NumCPU()/2)
	domainBig.FFT(res, fft.DIF, 0)
	return res
}

// computeH computes h in canonical form, split as h1+X^mh2+X^2mh3 such that
//
// qlL+qrR+qmL.R+qoO+k + alpha.(zu*g1*g2*g3*l-z*f1*f2*f3*l) + alpha**2*L1*(z-1)= h.Z
// \------------------/         \------------------------/             \-----/
//    constraintsInd			    constraintOrdering					startsAtOne
//
// constraintInd, constraintOrdering are evaluated on the odd cosets of (Z/8mZ)/(Z/mZ)
func computeH(pk *ProvingKey, constraintsInd, constraintOrdering, lsBz []fr.Element, alpha fr.Element) ([]fr.Element, []fr.Element, []fr.Element) {

	h := make([]fr.Element, pk.DomainBig.Cardinality)

	// evaluate Z = X**m-1 on the odd cosets of (Z/8mZ)/(Z/mZ), stored in u
	var bExpo big.Int
	bExpo.SetUint64(pk.DomainSmall.Cardinality)

	var u [8]fr.Element // 4 first entries are always used, the last 4 are for the case domainBig/domainNum=8
	var uu fr.Element
	var one fr.Element
	one.SetOne()
	uu.Set(&pk.DomainBig.Generator)
	u[0].Set(&pk.DomainBig.FinerGenerator)
	u[1].Mul(&u[0], &uu)
	u[2].Mul(&u[1], &uu)
	u[3].Mul(&u[2], &uu)
	toShift := pk.DomainBig.Cardinality / pk.DomainSmall.Cardinality
	if toShift == 8 {
		u[4].Mul(&u[3], &uu)
		u[5].Mul(&u[4], &uu)
		u[6].Mul(&u[5], &uu)
		u[7].Mul(&u[6], &uu)
	}
	u[0].Exp(u[0], &bExpo).Sub(&u[0], &one) // (X**m-1)**-1 at u
	u[1].Exp(u[1], &bExpo).Sub(&u[1], &one) // (X**m-1)**-1 at u**3
	u[2].Exp(u[2], &bExpo).Sub(&u[2], &one) // (X**m-1)**-1 at u**5
	u[3].Exp(u[3], &bExpo).Sub(&u[3], &one) // (X**m-1)**-1 at u**7
	if toShift == 8 {
		u[4].Exp(u[4], &bExpo).Sub(&u[4], &one) // (X**m-1)**-1 at u
		u[5].Exp(u[5], &bExpo).Sub(&u[5], &one) // (X**m-1)**-1 at u**3
		u[6].Exp(u[6], &bExpo).Sub(&u[6], &one) // (X**m-1)**-1 at u**5
		u[7].Exp(u[7], &bExpo).Sub(&u[7], &one) // (X**m-1)**-1 at u**7
	}

	_u := fr.BatchInvert(u[:])

	// computes L1 (canonical form)
	startsAtOne := make([]fr.Element, pk.DomainBig.Cardinality)
	for i := 0; i < int(pk.DomainSmall.Cardinality); i++ {
		startsAtOne[i].Set(&pk.DomainSmall.CardinalityInv)
	}
	pk.DomainBig.FFT(startsAtOne, fft.DIF, 1)

	// evaluate qlL+qrR+qmL.R+qoO+k + alpha.(zu*g1*g2*g3*l-z*f1*f2*f3*l) + alpha**2*L1(X)(Z(X)-1)
	// on the odd cosets of (Z/8mZ)/(Z/mZ)
	nn := uint64(64 - bits.TrailingZeros64(pk.DomainBig.Cardinality))

	utils.Parallelize(int(pk.DomainBig.Cardinality), func(start, end int) {
		var t fr.Element
		for i := uint64(start); i < uint64(end); i++ {
			t.Sub(&lsBz[i], &one) // evaluates L1*(z-1) on the odd cosets of (Z/8mZ)/(Z/4mZ)
			h[i].Mul(&startsAtOne[i], &alpha).Mul(&h[i], &t).
				Add(&h[i], &constraintOrdering[i]).
				Mul(&h[i], &alpha).
				Add(&h[i], &constraintsInd[i])

			// evaluate qlL+qrR+qmL.R+qoO+k + alpha.(zu*g1*g2*g3*l-z*f1*f2*f3*l)/Z
			// on the odd cosets of (Z/8mZ)/(Z/mZ)
			// note that h is still bit reversed here
			irev := bits.Reverse64(i) >> nn
			h[i].Mul(&h[i], &_u[irev%toShift])
		}
	})

	// put h in canonical form. h is of degree 3*(n+1)+2.
	// using fft.DIT put h revert bit reverse
	pk.DomainBig.FFTInverse(h, fft.DIT, 1)

	// degree of hi is n+2 because of the blinding
	h1 := h[:pk.DomainSmall.Cardinality+2]
	h2 := h[pk.DomainSmall.Cardinality+2 : 2*(pk.DomainSmall.Cardinality+2)]
	h3 := h[2*(pk.DomainSmall.Cardinality+2) : 3*(pk.DomainSmall.Cardinality+2)]

	return h1, h2, h3

}

// computeZ computes Z, in canonical basis, where:
//
// * Z of degree n (domainNum.Cardinality)
// * Z(1)=1
// 								   (l_i+z**i+gamma)*(r_i+u*z**i+gamma)*(o_i+u**2z**i+gamma)
// * for i>0: Z(u**i) = Pi_{k<i} -------------------------------------------------------
//								     (l_i+s1+gamma)*(r_i+s2+gamma)*(o_i+s3+gamma)
//
//	* l, r, o are the solution in Lagrange basis
func computeBlindedZ(l, r, o []fr.Element, pk *ProvingKey, beta, gamma fr.Element) ([]fr.Element, error) {

	// note that z has more capacity has its memory is reused for blinded z later on
	z := make([]fr.Element, pk.DomainSmall.Cardinality, pk.DomainSmall.Cardinality+3)
	nbElmts := int(pk.DomainSmall.Cardinality)
	gInv := make([]fr.Element, pk.DomainSmall.Cardinality)

	z[0].SetOne()
	gInv[0].SetOne()

	var one fr.Element
	one.SetOne()

	var shift fr.Element
	shift.SetUint64(pk.DomainSmall.Cardinality)

	utils.Parallelize(nbElmts-1, func(start, end int) {

		var f [3]fr.Element
		var g [3]fr.Element
		var u, v, w fr.Element

		for i := start; i < end; i++ {

			u.SetUint64(uint64(i))
			v.Add(&u, &shift)
			w.Add(&v, &shift)

			f[0].Mul(&u, &beta).Add(&f[0], &l[i]).Add(&f[0], &gamma) //l_i+i*beta+gamma
			f[1].Mul(&v, &beta).Add(&f[1], &r[i]).Add(&f[1], &gamma) //r_i+(i+n)*beta+gamma
			f[2].Mul(&w, &beta).Add(&f[2], &o[i]).Add(&f[2], &gamma) //o_i+(i+2n)*beta+gamma

			g[0].Mul(&pk.LId[pk.Permutation[i]], &beta).Add(&g[0], &l[i]).Add(&g[0], &gamma)           //l_i+s(i)*beta+gamma
			g[1].Mul(&pk.LId[pk.Permutation[i+nbElmts]], &beta).Add(&g[1], &r[i]).Add(&g[1], &gamma)   //r_i+s(i+n)*beta+gamma
			g[2].Mul(&pk.LId[pk.Permutation[i+2*nbElmts]], &beta).Add(&g[2], &o[i]).Add(&g[2], &gamma) //o_i+s(i+2n)*beta+gamma

			f[0].Mul(&f[0], &f[1]).Mul(&f[0], &f[2]) // (l_i+i*beta+gamma)*(r_i+(i+n)*beta+gamma)*(o_i+(i+2n)*beta+gamma)
			g[0].Mul(&g[0], &g[1]).Mul(&g[0], &g[2]) //  (l_i+s(i)*beta+gamma)*(r_i+s(i+n)*beta+gamma)*(o_i+s(i+2n)*beta+gamma)

			gInv[i+1] = g[0]
			z[i+1] = f[0]

		}
	})

	gInv = fr.BatchInvert(gInv)
	for i := 1; i < nbElmts; i++ {
		z[i].Mul(&z[i], &z[i-1]).
			Mul(&z[i], &gInv[i])
	}

	pk.DomainSmall.FFTInverse(z, fft.DIF, 0)
	fft.BitReverse(z)

	return blindPoly(z, pk.DomainSmall.Cardinality, 2)

}

// computeLRO extracts the solution l, r, o, and returns it in lagrange form.
// solution = [ public | secret | internal ]
func computeLRO(spr *cs.SparseR1CS, pk *ProvingKey, solution []fr.Element) ([]fr.Element, []fr.Element, []fr.Element) {

	s := int(pk.DomainSmall.Cardinality)

	var l, r, o []fr.Element
	l = make([]fr.Element, s)
	r = make([]fr.Element, s)
	o = make([]fr.Element, s)
	s0 := solution[0]

	for i := 0; i < spr.NbPublicVariables; i++ { // placeholders
		l[i] = solution[i]
		r[i] = s0
		o[i] = s0
	}
	offset := spr.NbPublicVariables
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

// computeBlindedLRO l, r, o in canonical basis with blinding
func computeBlindedLRO(ll, lr, lo []fr.Element, domain *fft.Domain) (bcl, bcr, bco []fr.Element, err error) {

	// note that bcl, bcr and bco reuses cl, cr and co memory
	cl := make([]fr.Element, domain.Cardinality, domain.Cardinality+2)
	cr := make([]fr.Element, domain.Cardinality, domain.Cardinality+2)
	co := make([]fr.Element, domain.Cardinality, domain.Cardinality+2)

	chDone := make(chan error, 2)

	go func() {
		var err error
		copy(cl, ll)
		domain.FFTInverse(cl, fft.DIF, 0)
		fft.BitReverse(cl)
		bcl, err = blindPoly(cl, domain.Cardinality, 1)
		chDone <- err
	}()
	go func() {
		var err error
		copy(cr, lr)
		domain.FFTInverse(cr, fft.DIF, 0)
		fft.BitReverse(cr)
		bcr, err = blindPoly(cr, domain.Cardinality, 1)
		chDone <- err
	}()
	copy(co, lo)
	domain.FFTInverse(co, fft.DIF, 0)
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
// pre condition degree(cp) <= rou + bo
// pre condition cap(cp) >= int(totalDegree + 1)
func blindPoly(cp []fr.Element, rou, bo uint64) ([]fr.Element, error) {

	// degree of the blinded polynomial is max(rou+order, cp.Degree)
	totalDegree := rou + bo

	// re-use cp
	res := cp[:totalDegree+1]

	// random polynomial
	blindingPoly := make([]fr.Element, bo+1)

	// TODO reactivate blinding, currently deactivated for testing purposes
	// for i := uint64(0); i < bo+1; i++ {
	// 	if _, err := blindingPoly[i].SetRandom(); err != nil {
	// 		return nil, err
	// 	}
	// }

	// blinding
	for i := uint64(0); i < bo+1; i++ {
		res[i].Sub(&res[i], &blindingPoly[i])
		res[rou+i].Add(&res[rou+i], &blindingPoly[i])
	}

	return res, nil
}
