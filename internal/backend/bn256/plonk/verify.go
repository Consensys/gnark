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
	"fmt"
	"math/big"

	bn256witness "github.com/consensys/gnark/internal/backend/bn256/witness"
	"github.com/consensys/gurvy/bn256/fr"
)

// VerifyRaw verifies a PLONK proof
// TODO use Fiat Shamir to derive the challenges
func VerifyRaw(proof *Proof, publicData *PublicRaw, publicWitness bn256witness.Witness) bool {

	// evaluation of ql, qr, qm, qo, qk at zeta
	var ql, qr, qm, qo, qk fr.Element
	_ql := publicData.Ql.Eval(&zeta)
	_qr := publicData.Qr.Eval(&zeta)
	_qm := publicData.Qm.Eval(&zeta)
	_qo := publicData.Qo.Eval(&zeta)
	_qk := publicData.Qk.Eval(&zeta)
	ql.Set(_ql.(*fr.Element))
	qr.Set(_qr.(*fr.Element))
	qm.Set(_qm.(*fr.Element))
	qo.Set(_qo.(*fr.Element))
	qk.Set(_qk.(*fr.Element))

	// evaluation of qlL+qrR+qmL.R+qoO+k at zeta
	var constraintInd fr.Element
	var qll, qrr, qmlr, qoo fr.Element
	qll.Mul(&ql, &proof.LROHZ[0])
	qrr.Mul(&qr, &proof.LROHZ[1])
	qmlr.Mul(&qm, &proof.LROHZ[0]).Mul(&qmlr, &proof.LROHZ[1])
	qoo.Mul(&qo, &proof.LROHZ[3])
	constraintInd.Add(&qll, &qrr).
		Add(&constraintInd, &qmlr).
		Add(&constraintInd, &qoo).
		Add(&constraintInd, &qk)

	// evaluation of zu*g1*g2*g3*l-z*f1*f2*f3*l at zeta
	var constraintOrdering, sZeta, ssZeta fr.Element
	var s, f, g [3]fr.Element

	s1 := publicData.CS1.Eval(&zeta)
	s2 := publicData.CS2.Eval(&zeta)
	s3 := publicData.CS3.Eval(&zeta)

	s[0].Set(s1.(*fr.Element))
	s[1].Set(s2.(*fr.Element))
	s[2].Set(s3.(*fr.Element))

	g[0].Add(&proof.LROHZ[0], &s[0]).Add(&g[0], &gamma) // l+s1+gamma
	g[1].Add(&proof.LROHZ[1], &s[1]).Add(&g[1], &gamma) // r+s2+gamma
	g[2].Add(&proof.LROHZ[2], &s[2]).Add(&g[2], &gamma) // o+s3+gamma
	g[0].Mul(&g[0], &g[1]).Mul(&g[0], &g[2]).Mul(&g[0], &proof.LROHZ[0])

	sZeta.Mul(&publicData.Shifter[0], &zeta)
	ssZeta.Mul(&publicData.Shifter[1], &zeta)

	f[0].Add(&proof.LROHZ[0], &zeta).Add(&f[0], &gamma)   // l+s1+gamma
	f[1].Add(&proof.LROHZ[1], &sZeta).Add(&f[1], &gamma)  // r+s2+gamma
	f[2].Add(&proof.LROHZ[2], &ssZeta).Add(&f[2], &gamma) // o+s3+gamma
	f[0].Mul(&f[0], &f[1]).Mul(&f[0], &f[2]).Mul(&f[0], &proof.LROHZ[0])

	g[0].Mul(&g[0], &proof.ZShift)
	f[0].Mul(&f[0], &proof.LROHZ[4])

	constraintOrdering.Sub(&g[0], &f[0])

	// evaluation of Z=X**m-1 at zeta
	var zzeta, one fr.Element
	var bExpo big.Int
	one.SetOne()
	bExpo.SetUint64(publicData.DomainNum.Cardinality)
	zzeta.Exp(zeta, &bExpo).Sub(&zzeta, &one)

	// lhs = qlL+qrR+qmL.R+qoO+k(zeta) + alpha*(zu*g1*g2*g3*l-z*f1*f2*f3*l)(zeta)
	// rhs = h(zeta)(zeta**m-1)
	var lhs, rhs fr.Element
	lhs.Mul(&alpha, &constraintOrdering).Add(&lhs, &constraintInd)
	rhs.Mul(&zzeta, &proof.LROHZ[4])

	// Verfiy commitments WIP
	fmt.Printf("lhs: %s\n", lhs.String())
	fmt.Printf("rhs: %s\n", rhs.String())

	if !lhs.Equal(&rhs) {
		return false
	}

	return true

}
