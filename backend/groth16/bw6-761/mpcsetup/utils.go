// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/internal/utils"
	"math/big"
	"math/bits"
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

// Returns [1, a, a², ..., aᴺ⁻¹ ]
func powers(a *fr.Element, N int) []fr.Element {
	if N == 0 {
		return nil
	}
	result := make([]fr.Element, N)
	result[0].SetOne()
	for i := 1; i < N; i++ {
		result[i].Mul(&result[i-1], a)
	}
	return result
}

// Returns [aᵢAᵢ, ...]∈𝔾₁
// it assumes len(A) ≤ len(a)
func scaleG1InPlace(A []curve.G1Affine, a []fr.Element) {
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
	utils.Parallelize(len(A), func(start, end int) {
		var tmp big.Int
		for i := start; i < end; i++ {
			a[i].BigInt(&tmp)
			A[i].ScalarMultiplication(&A[i], &tmp)
		}
	})
}
