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
	"math/big"

	"github.com/consensys/gnark/crypto/polynomial"
	"github.com/consensys/gnark/crypto/polynomial/bn256"
	"github.com/consensys/gnark/internal/backend/bn256/cs"
	"github.com/consensys/gnark/internal/backend/bn256/fft"
	bn256witness "github.com/consensys/gnark/internal/backend/bn256/witness"
	"github.com/consensys/gurvy/bn256/fr"
)

// Proof PLONK proofs, consisting of opening proofs
type Proof struct {
	L, R, O, H polynomial.OpeningProof
}

func computeLRO(spr *cs.SparseR1CS, publicData PublicRaw, witness bn256witness.Witness) (bn256.Poly, bn256.Poly, bn256.Poly) {

	solution, _ := spr.Solve(witness)

	s := publicData.DomainNum.Cardinality

	var l, r, o bn256.Poly
	l.Data = make([]fr.Element, s)
	r.Data = make([]fr.Element, s)
	o.Data = make([]fr.Element, s)

	for i := 0; i < len(spr.Constraints); i++ {
		l.Data[i].Set(&solution[spr.Constraints[i].L.VariableID()])
		r.Data[i].Set(&solution[spr.Constraints[i].R.VariableID()])
		o.Data[i].Set(&solution[spr.Constraints[i].O.VariableID()])
	}
	offset := len(spr.Constraints)
	for i := 0; i < len(spr.Assertions); i++ {
		l.Data[offset+i].Set(&solution[spr.Assertions[i].L.VariableID()])
		r.Data[offset+i].Set(&solution[spr.Assertions[i].R.VariableID()])
		o.Data[offset+i].Set(&solution[spr.Assertions[i].O.VariableID()])
	}

	return l, r, o

}

// evaluate evaluates a polynomial of degree m=domainNum.Cardinality on the 2 cosets
// 1 and 3 of (Z/4mZ)/(Z/mZ), so it dodges Z/mZ (+Z/2mZ), the vanishing set of Z.
//
// Puts the result in res (of size 2*domain.Cardinality).
//
// Both sizes of poly and res are powers of 2, len(res) = 2*len(poly).
func evaluate(poly, res []fr.Element, domain *fft.Domain) {

	// TODO play with DIT/DIF to minimize calls to BitReverse

	// express poly in the canonical basis
	domain.FFTInverse(poly, fft.DIF, 0)
	fft.BitReverse(poly)

	// build a copy of poly padded with 0 so it has the length of the closest power of 2 of poly
	evaluations := make([][]fr.Element, 2)
	evaluations[0] = make([]fr.Element, domain.Cardinality)
	evaluations[1] = make([]fr.Element, domain.Cardinality)

	copy(evaluations[0], poly)
	copy(evaluations[1], poly)

	fft.BitReverse(evaluations[0])
	fft.BitReverse(evaluations[1])
	domain.FFT(evaluations[0], fft.DIT, 1)
	domain.FFT(evaluations[1], fft.DIT, 3)

	//res := make([]fr.Element, 2*domain.Cardinality)
	for i := uint64(0); i < domain.Cardinality; i++ {
		res[2*i].Set(&evaluations[0][i])
		res[2*i+1].Set(&evaluations[1][i])
	}

}

// computeNumFirstClaim computes the evaluation of lL+qrR+qqmL.R+qoO+k on
// the coset 1 of (Z/4mZ)/(Z/2mZ), where m=nbConstraints+nbAssertions.
//
// qlL+qrR+qmL.R+qoO+k = H*Z, where Z=x^n-1
//
// l, r, o must be of size 2^n.
func computeNumFirstClaim(publicData PublicRaw, l, r, o []fr.Element) []fr.Element {

	// data
	evalL := make([]fr.Element, 2*publicData.DomainNum.Cardinality)
	evalR := make([]fr.Element, 2*publicData.DomainNum.Cardinality)
	evalO := make([]fr.Element, 2*publicData.DomainNum.Cardinality)

	evalQl := make([]fr.Element, 2*publicData.DomainNum.Cardinality)
	evalQr := make([]fr.Element, 2*publicData.DomainNum.Cardinality)
	evalQm := make([]fr.Element, 2*publicData.DomainNum.Cardinality)
	evalQo := make([]fr.Element, 2*publicData.DomainNum.Cardinality)
	evalQk := make([]fr.Element, 2*publicData.DomainNum.Cardinality)

	// public vectors
	evaluate(publicData.Ql.Data, evalQl, publicData.DomainNum)
	evaluate(publicData.Qr.Data, evalQr, publicData.DomainNum)
	evaluate(publicData.Qm.Data, evalQm, publicData.DomainNum)
	evaluate(publicData.Qo.Data, evalQo, publicData.DomainNum)
	evaluate(publicData.Qk.Data, evalQk, publicData.DomainNum)

	// solution vectors
	evaluate(l, evalL, publicData.DomainNum)
	evaluate(r, evalR, publicData.DomainNum)
	evaluate(o, evalO, publicData.DomainNum)

	// computes the evaluation of qrR+qlL+qmL.R+qoO+k on the coset
	// 1 of (Z/4mZ)/(Z/2mZ)
	var acc, buf fr.Element
	for i := uint64(0); i < 2*publicData.DomainNum.Cardinality; i++ {

		acc.Mul(&evalQl[i], &l[i]) // ql.l

		buf.Mul(&evalQr[i], &r[i])
		acc.Add(&acc, &buf) // ql.l + qr.r

		buf.Mul(&evalQm[i], &l[i]).Mul(&buf, &r[i])
		acc.Add(&acc, &buf) // ql.l + qr.r + qm.l.r

		buf.Mul(&evalQo[i], &o[i])
		acc.Add(&acc, &buf)        // ql.l + qr.r + qm.l.r + qo.o
		l[i].Add(&acc, &evalQk[i]) // ql.l + qr.r + qm.l.r + qo.o + k
	}

	return l
}

// computeH computes h = num/Z, where:
// * Z = X^m-1, m=2^n
// * num (of size 2^{n+1}) is the evaluation of a polynomial of
// 	degree 3*m on 2m=2^{n+1} points (coset 1 of (Z/2mZ)/(Z/mZ)).
// The result is h in the canonical basis.
func computeH(num []fr.Element) []fr.Element {

	s := uint64(len(num))
	domain := fft.NewDomain(s, 1)

	h := make([]fr.Element, domain.Cardinality)

	var evalEven, evalOdd fr.Element
	var expo big.Int
	sizeDomainZ := domain.Cardinality / 2

	expo.SetUint64(sizeDomainZ)
	evalEven.Exp(domain.FinerGenerator, &expo)
	expo.SetUint64(3 * sizeDomainZ)
	evalOdd.Exp(domain.FinerGenerator, &expo)

	// Z evaluated
	zPoly := make([]fr.Element, domain.Cardinality)
	for i := 0; i < int(sizeDomainZ); i++ {
		zPoly[2*i].Set(&evalEven)
		zPoly[2*i+1].Set(&evalOdd)
	}

	// h = num/Z
	for i := 0; i < int(domain.Cardinality); i++ {
		h[i].Div(&num[i], &zPoly[i])
	}

	// express h in the canonical basis
	domain.FFTInverse(h, fft.DIF, 1)
	fft.BitReverse(h)

	return h
}

// Prove from the public data representing a circuit, and the solution
// l, r, o, outputs a proof that the assignment is valid.
//
// It computes H such that qlL+qrR+qmL.R+qoO+k = H*Z, Z = X^m-1
func Prove(spr *cs.SparseR1CS, publicData PublicRaw, witness bn256witness.Witness) *Proof {

	// computes opening
	l, r, o := computeLRO(spr, publicData, witness)

	// evaluate qlL+qrR+qmL.R+qoO+k on 2*m points
	num := bn256.Poly{
		Data: computeNumFirstClaim(publicData, l.Data, r.Data, o.Data),
	}

	// TODO wip, compute the remaining part of the num

	// compute h (its evaluation)
	h := bn256.Poly{
		Data: computeH(num.Data),
	}

	// compute challenge
	// TODO use fiat Shamir to sample zeta
	var zeta fr.Element
	zeta.SetString("2938092839238274283")

	proof := &Proof{}
	proof.L = publicData.CommitmentScheme.Open(l, zeta)
	proof.R = publicData.CommitmentScheme.Open(r, zeta)
	proof.O = publicData.CommitmentScheme.Open(o, zeta)
	proof.H = publicData.CommitmentScheme.Open(h, zeta)

	return proof
}
