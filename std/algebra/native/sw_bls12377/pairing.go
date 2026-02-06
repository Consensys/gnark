// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

// GT target group of the pairing
type GT = fields_bls12377.E12

// binary decomposition of x₀=9586122913090633729 little endian
var loopCounter = [64]int8{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1}

// MillerLoop computes the product of n miller loops (n can be 1)
// ∏ᵢ { fᵢ_{x₀,Q}(P) }
func MillerLoop(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {

	// check input size match
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
	return millerLoopLines(api, P, lines)

}

// millerLoopLines computes the multi-Miller loop from points in G1 and precomputed lines in G2
func millerLoopLines(api frontend.API, P []G1Affine, lines []lineEvaluations) (GT, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(lines) {
		return GT{}, errors.New("invalid inputs sizes")
	}

	var res GT
	res.SetOne()
	var prodLines [5]fields_bls12377.E2
	var l0, l1 lineEvaluation

	// precomputations
	yInv := make([]frontend.Variable, n)
	xNegOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xNegOverY[k] = api.Mul(P[k].X, yInv[k])
		xNegOverY[k] = api.Neg(xNegOverY[k])
	}

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)

	// k = 0, separately to avoid MulBy034 (res × ℓ)
	// (assign line to res)
	// line evaluation at P[0]
	res.C1.B0.MulByFp(api, lines[0][0][62].R0, xNegOverY[0])
	res.C1.B1.MulByFp(api, lines[0][0][62].R1, yInv[0])

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		// line evaluation at P[1]

		// ℓ × res
		prodLines = *fields_bls12377.Mul034By034(api,
			*l0.R0.MulByFp(api, lines[1][0][62].R0, xNegOverY[1]),
			*l0.R1.MulByFp(api, lines[1][0][62].R1, yInv[1]),
			res.C1.B0,
			res.C1.B1,
		)
		res.C0.B0 = prodLines[0]
		res.C0.B1 = prodLines[1]
		res.C0.B2 = prodLines[2]
		res.C1.B0 = prodLines[3]
		res.C1.B1 = prodLines[4]

	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy034 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		// line evaluation at P[1]

		// ℓ × res
		res = *fields_bls12377.Mul01234By034(api,
			prodLines,
			*l0.R0.MulByFp(api, lines[2][0][62].R0, xNegOverY[2]),
			*l0.R1.MulByFp(api, lines[2][0][62].R1, yInv[2]),
		)

		// k >= 3
		for k := 3; k < n; k++ {
			// line evaluation at P[k]

			// ℓ × res
			res.MulBy034(api,
				*l0.R0.MulByFp(api, lines[k][0][62].R0, xNegOverY[k]),
				*l0.R1.MulByFp(api, lines[k][0][62].R1, yInv[k]),
			)
		}
	}

	// i = 61, separately to use a special E12 Square
	// k = 0
	// line evaluation at P[0]

	if n == 1 {
		res.Square034(api, res)
		prodLines[0] = res.C0.B0
		prodLines[1] = res.C0.B1
		prodLines[2] = res.C0.B2
		prodLines[3] = res.C1.B0
		prodLines[4] = res.C1.B1
		// ℓ × res
		res = *fields_bls12377.Mul01234By034(api,
			prodLines,
			*l0.R0.MulByFp(api, lines[0][0][61].R0, xNegOverY[0]),
			*l0.R1.MulByFp(api, lines[0][0][61].R1, yInv[0]),
		)

	} else {
		res.Square(api, res)
		// ℓ × res
		res.MulBy034(api,
			*l0.R0.MulByFp(api, lines[0][0][61].R0, xNegOverY[0]),
			*l0.R1.MulByFp(api, lines[0][0][61].R1, yInv[0]),
		)

	}

	for k := 1; k < n; k++ {
		// line evaluation at P[k]
		// ℓ × res
		res.MulBy034(api,
			*l0.R0.MulByFp(api, lines[k][0][61].R0, xNegOverY[k]),
			*l0.R1.MulByFp(api, lines[k][0][61].R1, yInv[k]),
		)
	}

	for i := 60; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res.Square(api, res)

		for k := 0; k < n; k++ {
			if loopCounter[i] == 0 {
				// line evaluation at P

				// ℓ × res
				res.MulBy034(api,
					*l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k]),
					*l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k]),
				)
				continue

			}

			// lines evaluation at P

			// ℓ × ℓ
			prodLines = *fields_bls12377.Mul034By034(api,
				*l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k]),
				*l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k]),
				*l1.R0.MulByFp(api, lines[k][1][i].R0, xNegOverY[k]),
				*l1.R1.MulByFp(api, lines[k][1][i].R1, yInv[k]),
			)
			// (ℓ × ℓ) × res
			res.MulBy01234(api, prodLines)
		}
	}
	return res, nil
}

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

// FinalExponentiation computes the exponentiation e1ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 3 (Hayashida et al.)
func FinalExponentiation(api frontend.API, e1 GT) GT {
	result := e1

	// https://eprint.iacr.org/2016/130.pdf
	var t0, t1, t2 GT

	// easy part
	// (p⁶-1)(p²+1)
	t0.Conjugate(api, result)
	t0.DivUnchecked(api, t0, result)
	result.FrobeniusSquare(api, t0).
		Mul(api, result, t0)
	t3 := result

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
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

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroup
func Pair(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	f, err := MillerLoop(api, P, Q)
	if err != nil {
		return GT{}, err
	}
	return FinalExponentiation(api, f), nil
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
	hint, err := api.NewHint(pairingCheckTorusHint, 18, inputs...)
	if err != nil {
		panic(err)
	}

	// Read residueWitness (E12) from hint
	var residueWitness GT
	residueWitness.C0.B0.A0 = hint[0]
	residueWitness.C0.B0.A1 = hint[1]
	residueWitness.C0.B1.A0 = hint[2]
	residueWitness.C0.B1.A1 = hint[3]
	residueWitness.C0.B2.A0 = hint[4]
	residueWitness.C0.B2.A1 = hint[5]
	residueWitness.C1.B0.A0 = hint[6]
	residueWitness.C1.B0.A1 = hint[7]
	residueWitness.C1.B1.A0 = hint[8]
	residueWitness.C1.B1.A1 = hint[9]
	residueWitness.C1.B2.A0 = hint[10]
	residueWitness.C1.B2.A1 = hint[11]

	// Read scalingFactor (E6) from hint
	var scalingFactor fields_bls12377.E6
	scalingFactor.B0.A0 = hint[12]
	scalingFactor.B0.A1 = hint[13]
	scalingFactor.B1.A0 = hint[14]
	scalingFactor.B1.A1 = hint[15]
	scalingFactor.B2.A0 = hint[16]
	scalingFactor.B2.A1 = hint[17]

	// Compute torusWitness = compress(residueWitness) in circuit using hint
	// This constrains the torus witness to be consistent with residueWitness
	torusWitness := fields_bls12377.TorusCompressWithHint(api, residueWitness)

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

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups
func PairingCheck(api frontend.API, P []G1Affine, Q []G2Affine) error {

	// check input size match
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
	hint, err := api.NewHint(pairingCheckHint, 18, inputs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	var residueWitness GT
	residueWitness.C0.B0.A0 = hint[0]
	residueWitness.C0.B0.A1 = hint[1]
	residueWitness.C0.B1.A0 = hint[2]
	residueWitness.C0.B1.A1 = hint[3]
	residueWitness.C0.B2.A0 = hint[4]
	residueWitness.C0.B2.A1 = hint[5]
	residueWitness.C1.B0.A0 = hint[6]
	residueWitness.C1.B0.A1 = hint[7]
	residueWitness.C1.B1.A0 = hint[8]
	residueWitness.C1.B1.A1 = hint[9]
	residueWitness.C1.B2.A0 = hint[10]
	residueWitness.C1.B2.A1 = hint[11]

	var scalingFactor fields_bls12377.E6
	// constrain cubicNonResiduePower to be in Fp6
	scalingFactor.B0.A0 = hint[12]
	scalingFactor.B0.A1 = hint[13]
	scalingFactor.B1.A0 = hint[14]
	scalingFactor.B1.A1 = hint[15]
	scalingFactor.B2.A0 = hint[16]
	scalingFactor.B2.A1 = hint[17]

	lines := make([]lineEvaluations, nQ)
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := computeLines(api, Q[i].P)
			Q[i].Lines = Qlines
		}
		lines[i] = *Q[i].Lines
	}

	// precomputations
	yInv := make([]frontend.Variable, nP)
	xNegOverY := make([]frontend.Variable, nP)
	for k := 0; k < nP; k++ {
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xNegOverY[k] = api.Mul(P[k].X, yInv[k])
		xNegOverY[k] = api.Neg(xNegOverY[k])
	}

	// init Miller loop accumulator to residueWitness to share the squarings
	// of residueWitness^{x₀}
	res := residueWitness

	var prodLines [5]fields_bls12377.E2
	var l0, l1 lineEvaluation

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	for i := 62; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res.Square(api, res)

		if loopCounter[i] == 0 {
			for k := 0; k < nP; k++ {
				// line evaluation at P
				// ℓ × res
				res.MulBy034(api,
					*l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k]),
					*l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k]),
				)
			}
		} else {
			// multiply by residueWitness when bit=1
			res.Mul(api, res, residueWitness)
			for k := 0; k < nP; k++ {
				// lines evaluation at P
				// ℓ × ℓ
				prodLines = *fields_bls12377.Mul034By034(api,
					*l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k]),
					*l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k]),
					*l1.R0.MulByFp(api, lines[k][1][i].R0, xNegOverY[k]),
					*l1.R1.MulByFp(api, lines[k][1][i].R1, yInv[k]),
				)
				// (ℓ × ℓ) × res
				res.MulBy01234(api, prodLines)
			}
		}
	}

	// Check that  res * scalingFactor == residueWitness^(q)
	// where u=0x8508c00000000001 is the BLS12-377 seed,
	// and residueWitness, scalingFactor from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitness^{x₀} since
	// we initialized the Miller loop accumulator with residueWitness.
	var t0, t1 GT
	t1.C0.Mul(api, res.C0, scalingFactor)
	t1.C1.Mul(api, res.C1, scalingFactor)
	t0.Frobenius(api, residueWitness)

	t0.AssertIsEqual(api, t1)

	return nil
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

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleAndAddStep(api frontend.API, p1, p2 *g2AffP) (g2AffP, *lineEvaluation, *lineEvaluation) {

	var n, d, l1, l2, x3, x4, y4 fields_bls12377.E2
	var line1, line2 lineEvaluation
	var p g2AffP

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// x3 =lambda1**2-(p1.x+p2.x)
	x3.Square(api, l1)
	n.Add(api, p1.X, p2.X)
	x3.Sub(api, x3, n)

	// omit y3 computation

	// compute line1
	line1.R0 = l1
	line1.R1.Mul(api, l1, p1.X).Sub(api, line1.R1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute x4 = lambda2**2-(x1+x3)
	x4.Square(api, l2)
	n.Add(api, p1.X, x3)
	x4.Sub(api, x4, n)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4.Sub(api, p1.X, x4).
		Mul(api, l2, y4).
		Sub(api, y4, p1.Y)

	p.X = x4
	p.Y = y4

	// compute line2
	line2.R0 = l2
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return p, &line1, &line2
}

// doubleStep doubles a point in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleStep(api frontend.API, p1 *g2AffP) (g2AffP, *lineEvaluation) {

	var n, d, l, xr, yr fields_bls12377.E2
	var p g2AffP
	var line lineEvaluation

	// lambda = 3*p1.x**2/2*p.y
	n.Square(api, p1.X).MulByFp(api, n, 3)
	d.MulByFp(api, p1.Y, 2)
	l.DivUnchecked(api, n, d)

	// xr = lambda**2-2*p1.x
	xr.Square(api, l)
	n.MulByFp(api, p1.X, 2)
	xr.Sub(api, xr, n)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(api, p1.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p1.Y)

	p.X = xr
	p.Y = yr

	line.R0 = l
	line.R1.Mul(api, l, p1.X).Sub(api, line.R1, p1.Y)

	return p, &line

}

// linesCompute computes the lines that goes through p1 and p2, and (p1+p2) and p1 but does not compute 2p1+p2
func linesCompute(api frontend.API, p1, p2 *g2AffP) (*lineEvaluation, *lineEvaluation) {

	var n, d, l1, l2, x3 fields_bls12377.E2
	var line1, line2 lineEvaluation

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// x3 =lambda1**2-p1.x-p2.x
	x3.Square(api, l1)
	n.Add(api, p1.X, p2.X)
	x3.Sub(api, x3, n)

	// omit y3 computation
	// compute line1
	line1.R0 = l1
	line1.R1.Mul(api, l1, p1.X).Sub(api, line1.R1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute line2
	line2.R0 = l2
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return &line1, &line2
}
