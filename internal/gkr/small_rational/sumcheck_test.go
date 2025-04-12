// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package gkr

import (
	"fmt"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/internal/small_rational/polynomial"
	"github.com/stretchr/testify/assert"
	"hash"

	"strings"
	"testing"
)

func testSumcheckSingleClaimMultilin(polyInt []uint64, hashGenerator func() hash.Hash) error {
	poly := make(polynomial.MultiLin, len(polyInt))
	for i, n := range polyInt {
		poly[i].SetUint64(n)
	}

	claim := singleMultilinClaim{g: poly.Clone()}

	proof, err := sumcheckProve(&claim, fiatshamir.WithHash(hashGenerator()))
	if err != nil {
		return err
	}

	var sb strings.Builder
	for _, p := range proof.partialSumPolys {

		sb.WriteString("\t{")
		for i := 0; i < len(p); i++ {
			sb.WriteString(p[i].String())
			if i+1 < len(p) {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("}\n")
	}

	lazyClaim := singleMultilinLazyClaim{g: poly, claimedSum: poly.Sum()}
	if err = sumcheckVerify(lazyClaim, proof, fiatshamir.WithHash(hashGenerator())); err != nil {
		return err
	}

	proof.partialSumPolys[0][0].Add(&proof.partialSumPolys[0][0], toElement(1))
	lazyClaim = singleMultilinLazyClaim{g: poly, claimedSum: poly.Sum()}
	if sumcheckVerify(lazyClaim, proof, fiatshamir.WithHash(hashGenerator())) == nil {
		return fmt.Errorf("bad proof accepted")
	}
	return nil
}

func TestSumcheckDeterministicHashSingleClaimMultilin(t *testing.T) {

	polys := [][]uint64{
		{1, 2, 3, 4},             // 1 + 2X₁ + X₂
		{1, 2, 3, 4, 5, 6, 7, 8}, // 1 + 4X₁ + 2X₂ + X₃
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // 1 + 8X₁ + 4X₂ + 2X₃ + X₄
	}

	const MaxStep = 4
	const MaxStart = 4
	hashGens := make([]func() hash.Hash, 0, MaxStart*MaxStep)

	for step := 0; step < MaxStep; step++ {
		for startState := 0; startState < MaxStart; startState++ {
			if step == 0 && startState == 1 { // unlucky case where a bad proof would be accepted
				continue
			}
			hashGens = append(hashGens, newMessageCounterGenerator(startState, step))
		}
	}

	for _, poly := range polys {
		for _, hashGen := range hashGens {
			assert.NoError(t, testSumcheckSingleClaimMultilin(poly, hashGen),
				"failed with poly %v and hashGen %v", poly, hashGen())
		}
	}
}
