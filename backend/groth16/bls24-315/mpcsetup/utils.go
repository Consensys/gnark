// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"bytes"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/internal/utils"
	"math/big"
	"math/bits"
	"runtime"
)

func bitReverse[T any](a []T) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

func linearCombCoeffs(n int) []fr.Element {
	return bivariateRandomMonomials(n)
}

// Returns [1, a, a², ..., aᴺ⁻¹ ]
func powers(a *fr.Element, n int) []fr.Element {

	result := make([]fr.Element, n)
	if n >= 1 {
		result[0].SetOne()
	}
	if n >= 2 {
		result[1].Set(a)
	}
	for i := 2; i < n; i++ {
		result[i].Mul(&result[i-1], a)
	}
	return result
}

// Returns [aᵢAᵢ, ...]∈𝔾₁
// it assumes len(A) ≤ len(a)
func scaleG1InPlace(A []curve.G1Affine, a []fr.Element) {
	/*if a[0].IsOne() {
		A = A[1:]
		a = a[1:]
	}*/
	utils.Parallelize(len(A), func(start, end int) {
		var tmp big.Int
		for i := start; i < end; i++ {
			a[i].BigInt(&tmp)
			A[i].ScalarMultiplication(&A[i], &tmp)
		}
	})
}

// Returns [aᵢAᵢ, ...]∈𝔾₂
// it assumes len(A) ≤ len(a)
func scaleG2InPlace(A []curve.G2Affine, a []fr.Element) {
	/*if a[0].IsOne() {
		A = A[1:]
		a = a[1:]
	}*/
	utils.Parallelize(len(A), func(start, end int) {
		var tmp big.Int
		for i := start; i < end; i++ {
			a[i].BigInt(&tmp)
			A[i].ScalarMultiplication(&A[i], &tmp)
		}
	})
}

// Check n₁/d₁ = n₂/d₂ i.e. e(n₁, d₂) = e(d₁, n₂). No subgroup checks.
func sameRatioUnsafe(n1, d1 curve.G1Affine, n2, d2 curve.G2Affine) bool {
	var nd1 curve.G1Affine
	nd1.Neg(&d1)
	res, err := curve.PairingCheck(
		[]curve.G1Affine{n1, nd1},
		[]curve.G2Affine{d2, n2})
	if err != nil {
		panic(err)
	}
	return res
}

// returns ∑ rᵢAᵢ
func linearCombination(A []curve.G1Affine, r []fr.Element) curve.G1Affine {
	nc := runtime.NumCPU()
	var res curve.G1Affine
	if _, err := res.MultiExp(A, r[:len(A)], ecc.MultiExpConfig{NbTasks: nc}); err != nil {
		panic(err)
	}
	return res
}

// linearCombinationsG1 returns
//
//		powers[0].A[0] + powers[1].A[1] + ... + powers[ends[0]-2].A[ends[0]-2]
//	  + powers[ends[0]].A[ends[0]] + ... + powers[ends[1]-2].A[ends[1]-2]
//	    ....       (truncated)
//
//		powers[0].A[1] + powers[1].A[2] + ... + powers[ends[0]-2].A[ends[0]-1]
//	  + powers[ends[0]].A[ends[0]+1]  + ... + powers[ends[1]-2].A[ends[1]-1]
//	    ....       (shifted)
//
// It is assumed without checking that powers[i+1] = powers[i]*powers[1] unless i+1 is a partial sum of sizes.
// Also assumed that powers[0] = 1.
// The slices powers and A will be modified
func linearCombinationsG1(A []curve.G1Affine, powers []fr.Element, ends []int) (truncated, shifted curve.G1Affine) {
	if ends[len(ends)-1] != len(A) || len(A) != len(powers) {
		panic("lengths mismatch")
	}

	// zero out the large coefficients
	for i := range ends {
		powers[ends[i]-1].SetZero()
	}

	msmCfg := ecc.MultiExpConfig{NbTasks: runtime.NumCPU()}

	if _, err := truncated.MultiExp(A, powers, msmCfg); err != nil {
		panic(err)
	}

	var rInvNeg fr.Element
	rInvNeg.Inverse(&powers[1])
	rInvNeg.Neg(&rInvNeg)
	prevEnd := 0

	// r⁻¹.truncated =
	//		r⁻¹.powers[0].A[0] + powers[0].A[1] + ... + powers[ends[0]-3].A[ends[0]-2]
	//	  + r⁻¹.powers[ends[0]].A[ends[0]] + ... + powers[ends[1]-3].A[ends[1]-2]
	//	    ...
	//
	// compute shifted as
	//    - r⁻¹.powers[0].A[0] - r⁻¹.powers[ends[0]].A[ends[0]] - ...
	//    + powers[ends[0]-2].A[ends[0]-1] + powers[ends[1]-2].A[ends[1]-1] + ...
	//    + r⁻¹.truncated
	for i := range ends {
		powers[2*i].Mul(&powers[prevEnd], &rInvNeg)
		powers[2*i+1] = powers[ends[i]-2]
		A[2*i] = A[prevEnd]
		A[2*i+1] = A[ends[i]-1]
		prevEnd = ends[i]
	}
	powers[2*len(ends)].Neg(&rInvNeg) // r⁻¹: coefficient for truncated
	A[2*len(ends)] = truncated

	// TODO @Tabaie O(1) MSM worth it?
	if _, err := shifted.MultiExp(A[:2*len(ends)+1], powers[:2*len(ends)+1], msmCfg); err != nil {
		panic(err)
	}

	return
}

// linearCombinationsG2 assumes, and does not check, that rPowers[i+1] = rPowers[1].rPowers[i] for all applicable i
// Also assumed that 3 ≤ N ≔ len(A) ≤ len(rPowers).
// The results are truncated = ∑_{i=0}^{N-2} rⁱAᵢ, shifted = ∑_{i=1}^{N-1} rⁱAᵢ
func linearCombinationsG2(A []curve.G2Affine, rPowers []fr.Element) (truncated, shifted curve.G2Affine) {

	N := len(A)

	if _, err := shifted.MultiExp(A[1:], rPowers[:N-1], ecc.MultiExpConfig{NbTasks: runtime.NumCPU()}); err != nil {
		panic(err)
	}

	// truncated = r.shifted - rᴺ⁻¹.A[N-1] + A[0]
	var (
		x fr.Element
		i big.Int
	)
	x.Neg(&rPowers[N-2])
	x.BigInt(&i)
	truncated.
		ScalarMultiplication(&A[N-1], &i). // - rᴺ⁻².A[N-1]
		Add(&truncated, &shifted)          // shifted - rᴺ⁻².A[N-1]

	rPowers[1].BigInt(&i)
	truncated.
		ScalarMultiplication(&truncated, &i). // r.shifted - rᴺ⁻¹.A[N-1]
		Add(&truncated, &A[0])                // r.shifted - rᴺ⁻¹.A[N-1] + A[0]

	return
}

// Generate R∈𝔾₂ as Hash(gˢ, gˢˣ, challenge, dst)
// it is to be used as a challenge for generating a proof of knowledge to x
// π ≔ x.r; e([1]₁, π) =﹖ e([x]₁, r)
func genR(sG1 curve.G1Affine, challenge []byte, dst byte) curve.G2Affine {
	var buf bytes.Buffer
	buf.Grow(len(challenge) + curve.SizeOfG1AffineUncompressed*2)
	buf.Write(sG1.Marshal())
	buf.Write(challenge)
	spG2, err := curve.HashToG2(buf.Bytes(), []byte{dst})
	if err != nil {
		panic(err)
	}
	return spG2
}

type pair struct {
	g1 curve.G1Affine
	g2 *curve.G2Affine // optional; some values expect to have a 𝔾₂ representation, some don't.
}

// check that g1, g2 are valid as updated values, i.e. in their subgroups, and non-zero
func (p *pair) validUpdate() bool {
	// if the contribution is 0 the product is doomed to be 0.
	// no need to check this for g2 independently because if g1 is 0 and g2 is not, consistency checks will fail
	return !p.g1.IsInfinity() && p.g1.IsInSubGroup() && (p.g2 == nil || p.g2.IsInSubGroup())
}

type valueUpdate struct {
	contributionCommitment curve.G1Affine // x or [Xⱼ]₁
	contributionPok        curve.G2Affine // π ≔ x.r ∈ 𝔾₂
}

// newValueUpdate produces values associated with contribution to an existing value.
// the second output is toxic waste. It is the caller's responsibility to safely "dispose" of it.
func newValueUpdate(challenge []byte, dst byte) (proof valueUpdate, contributionValue fr.Element) {
	if _, err := contributionValue.SetRandom(); err != nil {
		panic(err)
	}
	var contributionValueI big.Int
	contributionValue.BigInt(&contributionValueI)

	_, _, gen1, _ := curve.Generators()
	proof.contributionCommitment.ScalarMultiplication(&gen1, &contributionValueI)

	// proof of knowledge to commitment. Algorithm 3 from section 3.7
	pokBase := genR(proof.contributionCommitment, challenge, dst) // r
	proof.contributionPok.ScalarMultiplication(&pokBase, &contributionValueI)

	return
}

// TODO @Tabaie batchVerify(denomG1, numG1 []G1Affine, denomG2, numG2 []G2Affine, challenge, dst)
// option for linear combination vector

// verify corresponds with verification steps {i, i+3} with 1 ≤ i ≤ 3 in section 7.1 of Bowe-Gabizon17
// it checks the proof of knowledge of the contribution, and the fact that the product of the contribution
// and previous commitment makes the new commitment.
// prevCommitment is assumed to be valid. No subgroup check and the like.
func (x *valueUpdate) verify(denom, num pair, challenge []byte, dst byte) error {
	noG2 := denom.g2 == nil
	if noG2 != (num.g2 == nil) {
		return errors.New("erasing or creating g2 values")
	}

	if !x.contributionPok.IsInSubGroup() || !x.contributionCommitment.IsInSubGroup() || !num.validUpdate() {
		return errors.New("contribution values subgroup check failed")
	}

	// verify commitment proof of knowledge. CheckPOK, algorithm 4 from section 3.7
	r := genR(x.contributionCommitment, challenge, dst) // verification challenge in the form of a g2 base
	_, _, g1, _ := curve.Generators()
	if !sameRatioUnsafe(x.contributionCommitment, g1, x.contributionPok, r) { // π =? x.r i.e. x/g1 =? π/r
		return errors.New("contribution proof of knowledge verification failed")
	}

	// check that the num/denom ratio is consistent between the 𝔾₁ and 𝔾₂ representations. Based on CONSISTENT, algorithm 2 in Section 3.6.
	if !noG2 && !sameRatioUnsafe(num.g1, denom.g1, *num.g2, *denom.g2) {
		return errors.New("g2 update inconsistent")
	}

	// now verify that num₁/denom₁ = x ( = x/g1 = π/r )
	// have to use the latter value for the RHS because we sameRatio needs both 𝔾₁ and 𝔾₂ values
	if !sameRatioUnsafe(num.g1, denom.g1, x.contributionPok, r) {
		return errors.New("g1 update inconsistent")
	}

	return nil
}

func toRefs[T any](s []T) []*T {
	res := make([]*T, len(s))
	for i := range s {
		res[i] = &s[i]
	}
	return res
}

func areInSubGroup[T interface{ IsInSubGroup() bool }](s []T) bool {
	for i := range s {
		if !s[i].IsInSubGroup() {
			return false
		}
	}
	return true
}

func areInSubGroupG1(s []curve.G1Affine) bool {
	return areInSubGroup(toRefs(s))
}

func areInSubGroupG2(s []curve.G2Affine) bool {
	return areInSubGroup(toRefs(s))
}

// bivariateRandomMonomials returns 1, x, ..., x^{ends[0]-1}; y, xy, ..., x^{ends[1]-ends[0]-1}y; ...
// all concatenated in the same slice
func bivariateRandomMonomials(ends ...int) []fr.Element {
	if len(ends) == 0 {
		return nil
	}

	res := make([]fr.Element, ends[len(ends)-1])
	if _, err := res[1].SetRandom(); err != nil {
		panic(err)
	}
	setPowers(res[:ends[0]])

	if len(ends) == 1 {
		return res
	}

	y := make([]fr.Element, len(ends))
	if _, err := y[1].SetRandom(); err != nil {
		panic(err)
	}
	setPowers(y)

	for d := 1; d < len(ends); d++ {
		xdeg := ends[d] - ends[d-1]
		if xdeg > ends[0] {
			panic("impl detail: first maximum degree for x must be the greatest")
		}

		for i := range xdeg {
			res[ends[d-1]+i].Mul(&res[i], &y[d])
		}
	}

	return res
}

// sets x[i] = x[1]ⁱ
func setPowers(x []fr.Element) {
	if len(x) == 0 {
		return
	}
	x[0].SetOne()
	for i := 2; i < len(x); i++ {
		x[i].Mul(&x[i-1], &x[1])
	}
}

func partialSums(s ...int) []int {
	if len(s) == 0 {
		return nil
	}
	sums := make([]int, len(s))
	sums[0] = s[0]
	for i := 1; i < len(s); i++ {
		sums[i] = sums[i-1] + s[i]
	}
	return sums
}

func beaconContributions(hash, beaconChallenge []byte, n int) []fr.Element {
	var (
		bb  bytes.Buffer
		err error
	)
	bb.Grow(len(hash) + len(beaconChallenge))
	bb.Write(hash)
	bb.Write(beaconChallenge)

	res := make([]fr.Element, 1)

	allNonZero := func() bool {
		for i := range res {
			if res[i].IsZero() {
				return false
			}
		}
		return true
	}

	// cryptographically unlikely for this to be run more than once
	for !allNonZero() {
		if res, err = fr.Hash(bb.Bytes(), []byte("Groth16 SRS generation ceremony - Phase 1 Final Step"), n); err != nil {
			panic(err)
		}
		bb.WriteByte('=') // padding just so that the hash is different next time
	}

	return res
}
