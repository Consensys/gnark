// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

// MillerLoopTorus computes the product of n miller loops using torus-based arithmetic
// The result is already in the cyclotomic subgroup (projected via p^6-1 during the loop)
// ∏ᵢ { fᵢ_{x₀,Q}(P)^(p^6-1) }
func MillerLoopTorus(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	n := len(P)
	if n == 0 || n != len(Q) {
		return GT{}, errors.New("invalid inputs sizes")
	}
	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := computeLines(api, Q[i].P)
			Q[i].Lines = Qlines
		}
		lines[i] = *Q[i].Lines
	}
	return millerLoopLinesTorus(api, P, lines)
}

// FinalExponentiationTorus computes the final exponentiation for a torus Miller loop result
// Since the p^6-1 part is already done in the torus Miller loop, we only compute (p²+1)(p⁴-p²+1)/r
// We use the cofactor 3 (Hayashida et al.): d = 3·(p²+1)(p⁴-p²+1)/r
func FinalExponentiationTorus(api frontend.API, e1 GT) GT {
	// e1 is already conjugated by p^6-1 from the torus Miller loop
	// Now compute (p²+1) part
	var t0 GT
	t0.FrobeniusSquare(api, e1)
	result := t0
	result.Mul(api, result, e1)
	t3 := result

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	var t1, t2 GT
	t0.ExpX0Minus1Square(api, result)
	t1.ExpX0(api, t0)
	t2.Frobenius(api, t0)
	result.Mul(api, t1, t2)
	t0.Conjugate(api, result)
	t1.ExpX0(api, result)
	t1.ExpX0(api, t1)
	t2.FrobeniusSquare(api, result)
	result.Mul(api, t1, t2)
	result.Mul(api, result, t0)
	t0.CyclotomicSquare(api, t3)
	t0.Mul(api, t0, t3)
	result.Mul(api, result, t0)
	return result
}

// PairTorus calculates the reduced pairing using torus-based Miller loop
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroup
func PairTorus(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	f, err := MillerLoopTorus(api, P, Q)
	if err != nil {
		return GT{}, err
	}
	return FinalExponentiationTorus(api, f), nil
}

// PairingCheckTorus calculates the reduced pairing using torus-based Miller loop
// and asserts if the result is One using hint verification with squaring sharing
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups
func PairingCheckTorus(api frontend.API, P []G1Affine, Q []G2Affine) error {
	nP := len(P)
	nQ := len(Q)
	if nP == 0 || nP != nQ {
		return errors.New("invalid inputs sizes")
	}

	// hint the non-residue witness
	inputs := make([]frontend.Variable, 0, 2*nP+4*nQ)
	for _, p := range P {
		inputs = append(inputs, p.X, p.Y)
	}
	for _, q := range Q {
		inputs = append(inputs, q.P.X.A0, q.P.X.A1, q.P.Y.A0, q.P.Y.A1)
	}
	hint, err := api.NewHint(pairingCheckTorusHint, 12, inputs...)
	if err != nil {
		panic(err)
	}

	// Read torusWitness (E6) directly from hint
	var torusWitness fields_bls12377.E6
	torusWitness.B0.A0 = hint[0]
	torusWitness.B0.A1 = hint[1]
	torusWitness.B1.A0 = hint[2]
	torusWitness.B1.A1 = hint[3]
	torusWitness.B2.A0 = hint[4]
	torusWitness.B2.A1 = hint[5]

	// Read scalingFactor (E6) from hint
	var scalingFactor fields_bls12377.E6
	scalingFactor.B0.A0 = hint[6]
	scalingFactor.B0.A1 = hint[7]
	scalingFactor.B1.A0 = hint[8]
	scalingFactor.B1.A1 = hint[9]
	scalingFactor.B2.A0 = hint[10]
	scalingFactor.B2.A1 = hint[11]

	// Compute torus Miller loop with hint-sharing
	lines := make([]lineEvaluations, nQ)
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := computeLines(api, Q[i].P)
			Q[i].Lines = Qlines
		}
		lines[i] = *Q[i].Lines
	}
	res := millerLoopLinesTorusWithWitness(api, P, lines, torusWitness)

	// Compute expected = compress(Frob(residueWitness) / scalingFactor) entirely in torus
	// Formula: expected = 2·z / (1 + s + z²·v·(1 - s)) where z = FrobeniusTorus(torusWitness)
	expected := fields_bls12377.CompressFrobDivideByScaling(api, torusWitness, scalingFactor)

	// Verify in torus form (no decompression needed!)
	res.AssertIsEqual(api, expected)

	return nil
}

// millerLoopLinesTorusWithWitness computes the torus Miller loop with hint-sharing
// It initializes the accumulator with torusWitness and multiplies by it at bit=1 positions
func millerLoopLinesTorusWithWitness(api frontend.API, P []G1Affine, lines []lineEvaluations, torusWitness fields_bls12377.E6) fields_bls12377.E6 {
	n := len(P)

	// Initialize accumulator with torus-compressed witness
	acc := torusWitness

	var l0 lineEvaluation

	// precomputations
	yInv := make([]frontend.Variable, n)
	xNegOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xNegOverY[k] = api.Mul(P[k].X, yInv[k])
		xNegOverY[k] = api.Neg(xNegOverY[k])
	}

	// Main loop: i = 62 down to 0
	for i := 62; i >= 0; i-- {
		// Square in torus
		acc = fields_bls12377.TorusSquareWithHint(api, acc)

		if loopCounter[i] == 0 {
			// Single line per pair at this bit
			for k := 0; k < n; k++ {
				l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k])
				l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k])
				// Negate for torus: l^(p^6-1) = (-c3, -c4, 0)
				var negL0, negL1 fields_bls12377.E2
				negL0.Neg(api, l0.R0)
				negL1.Neg(api, l0.R1)
				acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL0, negL1)
			}
		} else {
			// At bit=1: multiply by torusWitness to share squarings
			acc = fields_bls12377.TorusMulWithHint(api, acc, torusWitness)

			// Two lines per pair at this bit (doubling + addition)
			for k := 0; k < n; k++ {
				// First line
				l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k])
				l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k])
				var negL0, negL1 fields_bls12377.E2
				negL0.Neg(api, l0.R0)
				negL1.Neg(api, l0.R1)
				acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL0, negL1)

				// Second line
				var l1 lineEvaluation
				l1.R0.MulByFp(api, lines[k][1][i].R0, xNegOverY[k])
				l1.R1.MulByFp(api, lines[k][1][i].R1, yInv[k])
				var negL1_0, negL1_1 fields_bls12377.E2
				negL1_0.Neg(api, l1.R0)
				negL1_1.Neg(api, l1.R1)
				acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL1_0, negL1_1)
			}
		}
	}

	return acc
}

// millerLoopLinesTorus computes the multi-Miller loop using torus-based arithmetic
// This operates in the cyclotomic subgroup using E6 representation
func millerLoopLinesTorus(api frontend.API, P []G1Affine, lines []lineEvaluations) (GT, error) {
	n := len(P)
	if n == 0 || n != len(lines) {
		return GT{}, errors.New("invalid inputs sizes")
	}

	// Accumulator in torus representation
	// y = 0 represents 1 in E12 since (1 + 0·w) / (1 - 0·w) = 1
	var acc fields_bls12377.E6

	var l0 lineEvaluation

	// precomputations
	yInv := make([]frontend.Variable, n)
	xNegOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xNegOverY[k] = api.Mul(P[k].X, yInv[k])
		xNegOverY[k] = api.Neg(xNegOverY[k])
	}

	// i = 62: first iteration, acc = 0
	// Torus square of 0 is 0: y' = 2*0 / (1 + 0) = 0
	// So we just need to multiply by the first line
	// Line l = (1, 0, 0, c3, c4, 0) in E12
	// l^(p^6-1) in torus form = (-c3, -c4, 0) (negated line coefficients)

	// k = 0: first line
	var l0Neg, l1Neg fields_bls12377.E2
	l0Neg.MulByFp(api, lines[0][0][62].R0, xNegOverY[0])
	l1Neg.MulByFp(api, lines[0][0][62].R1, yInv[0])
	// Negate for torus: l^(p^6-1) = (-c3, -c4, 0)
	l0Neg.Neg(api, l0Neg)
	l1Neg.Neg(api, l1Neg)

	// First line: acc = (0 + sparse) / (1 + 0·sparse·v) = sparse
	acc.B0 = l0Neg
	acc.B1 = l1Neg
	// acc.B2 = 0 (must set as circuit zero)
	acc.B2.A0 = 0
	acc.B2.A1 = 0

	// Remaining lines for i = 62
	for k := 1; k < n; k++ {
		l0.R0.MulByFp(api, lines[k][0][62].R0, xNegOverY[k])
		l0.R1.MulByFp(api, lines[k][0][62].R1, yInv[k])
		// Negate for torus
		var negL0, negL1 fields_bls12377.E2
		negL0.Neg(api, l0.R0)
		negL1.Neg(api, l0.R1)
		acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL0, negL1)
	}

	// Main loop: i = 61 down to 0
	for i := 61; i >= 0; i-- {
		// Square in torus
		acc = fields_bls12377.TorusSquareWithHint(api, acc)

		for k := 0; k < n; k++ {
			if loopCounter[i] == 0 {
				// Single line at this bit
				l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k])
				l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k])
				// Negate for torus: l^(p^6-1) = (-c3, -c4, 0)
				var negL0, negL1 fields_bls12377.E2
				negL0.Neg(api, l0.R0)
				negL1.Neg(api, l0.R1)
				acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL0, negL1)
			} else {
				// Two lines at this bit (doubling + addition)
				// First line
				l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k])
				l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k])
				var negL0, negL1 fields_bls12377.E2
				negL0.Neg(api, l0.R0)
				negL1.Neg(api, l0.R1)
				acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL0, negL1)

				// Second line
				var l1 lineEvaluation
				l1.R0.MulByFp(api, lines[k][1][i].R0, xNegOverY[k])
				l1.R1.MulByFp(api, lines[k][1][i].R1, yInv[k])
				var negL1_0, negL1_1 fields_bls12377.E2
				negL1_0.Neg(api, l1.R0)
				negL1_1.Neg(api, l1.R1)
				acc = fields_bls12377.TorusMulBy01WithHint(api, acc, negL1_0, negL1_1)
			}
		}
	}

	// Decompress back to E12
	// The result is already in the cyclotomic subgroup (projected via p^6-1)
	// We need to get back to E12 representation
	result := fields_bls12377.TorusDecompressWithHint(api, acc)

	return result, nil
}
