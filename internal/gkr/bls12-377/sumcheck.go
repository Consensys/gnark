// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package gkr

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/polynomial"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"strconv"
)

// This does not make use of parallelism and represents polynomials as lists of coefficients
// It is currently geared towards arithmetic hashes. Once we have a more unified hash function interface, this can be generified.

// sumcheckClaims to a multi-sumcheck statement. i.e. one of the form ∑_{0≤i<2ⁿ} fⱼ(i) = cⱼ for 1 ≤ j ≤ m.
// Later evolving into a claim of the form gⱼ = ∑_{0≤i<2ⁿ⁻ʲ} g(r₁, r₂, ..., rⱼ₋₁, Xⱼ, i...)
type sumcheckClaims interface {
	combine(a fr.Element) polynomial.Polynomial // combine into the 0ᵗʰ sumcheck subclaim. Create g := ∑_{1≤j≤m} aʲ⁻¹fⱼ for which now we seek to prove ∑_{0≤i<2ⁿ} g(i) = c := ∑_{1≤j≤m} aʲ⁻¹cⱼ. Return g₁.
	next(fr.Element) polynomial.Polynomial      // Return the evaluations gⱼ(k) for 1 ≤ k < degⱼ(g). Update the claim to gⱼ₊₁ for the input value as rⱼ
	varsNum() int                               // number of variables
	claimsNum() int                             // number of claims
	proveFinalEval(r []fr.Element) []fr.Element // in case it is difficult for the verifier to compute g(r₁, ..., rₙ) on its own, the prover can provide the value and a proof
}

// sumcheckLazyClaims is the sumcheckClaims data structure on the verifier side. It is "lazy" in that it has to compute fewer things.
type sumcheckLazyClaims interface {
	claimsNum() int                      // claimsNum = m
	varsNum() int                        // varsNum = n
	combinedSum(a fr.Element) fr.Element // combinedSum returns c = ∑_{1≤j≤m} aʲ⁻¹cⱼ
	degree(i int) int                    // degree of the total claim in the i'th variable
	verifyFinalEval(r []fr.Element, combinationCoeff fr.Element, purportedValue fr.Element, proof []fr.Element) error
}

// sumcheckProof of a multi-statement.
type sumcheckProof struct {
	partialSumPolys []polynomial.Polynomial `json:"partialSumPolys"`
	finalEvalProof  []fr.Element            `json:"finalEvalProof"` //in case it is difficult for the verifier to compute g(r₁, ..., rₙ) on its own, the prover can provide the value and a proof
}

func setupTranscript(claimsNum int, varsNum int, settings *fiatshamir.Settings) (challengeNames []string, err error) {
	numChallenges := varsNum
	if claimsNum >= 2 {
		numChallenges++
	}
	challengeNames = make([]string, numChallenges)
	if claimsNum >= 2 {
		challengeNames[0] = settings.Prefix + "comb"
	}
	prefix := settings.Prefix + "pSP."
	for i := 0; i < varsNum; i++ {
		challengeNames[i+numChallenges-varsNum] = prefix + strconv.Itoa(i)
	}
	if settings.Transcript == nil {
		transcript := fiatshamir.NewTranscript(settings.Hash, challengeNames...)
		settings.Transcript = transcript
	}

	for i := range settings.BaseChallenges {
		if err = settings.Transcript.Bind(challengeNames[0], settings.BaseChallenges[i]); err != nil {
			return
		}
	}
	return
}

func next(transcript *fiatshamir.Transcript, bindings []fr.Element, remainingChallengeNames *[]string) (fr.Element, error) {
	challengeName := (*remainingChallengeNames)[0]
	for i := range bindings {
		bytes := bindings[i].Bytes()
		if err := transcript.Bind(challengeName, bytes[:]); err != nil {
			return fr.Element{}, err
		}
	}
	var res fr.Element
	bytes, err := transcript.ComputeChallenge(challengeName)
	res.SetBytes(bytes)

	*remainingChallengeNames = (*remainingChallengeNames)[1:]

	return res, err
}

// sumcheckProve create a non-interactive proof
func sumcheckProve(claims sumcheckClaims, transcriptSettings fiatshamir.Settings) (sumcheckProof, error) {

	var proof sumcheckProof
	remainingChallengeNames, err := setupTranscript(claims.claimsNum(), claims.varsNum(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return proof, err
	}

	var combinationCoeff fr.Element
	if claims.claimsNum() >= 2 {
		if combinationCoeff, err = next(transcript, []fr.Element{}, &remainingChallengeNames); err != nil {
			return proof, err
		}
	}

	varsNum := claims.varsNum()
	proof.partialSumPolys = make([]polynomial.Polynomial, varsNum)
	proof.partialSumPolys[0] = claims.combine(combinationCoeff)
	challenges := make([]fr.Element, varsNum)

	for j := 0; j+1 < varsNum; j++ {
		if challenges[j], err = next(transcript, proof.partialSumPolys[j], &remainingChallengeNames); err != nil {
			return proof, err
		}
		proof.partialSumPolys[j+1] = claims.next(challenges[j])
	}

	if challenges[varsNum-1], err = next(transcript, proof.partialSumPolys[varsNum-1], &remainingChallengeNames); err != nil {
		return proof, err
	}

	proof.finalEvalProof = claims.proveFinalEval(challenges)

	return proof, nil
}

func sumcheckVerify(claims sumcheckLazyClaims, proof sumcheckProof, transcriptSettings fiatshamir.Settings) error {
	remainingChallengeNames, err := setupTranscript(claims.claimsNum(), claims.varsNum(), &transcriptSettings)
	transcript := transcriptSettings.Transcript
	if err != nil {
		return err
	}

	var combinationCoeff fr.Element

	if claims.claimsNum() >= 2 {
		if combinationCoeff, err = next(transcript, []fr.Element{}, &remainingChallengeNames); err != nil {
			return err
		}
	}

	r := make([]fr.Element, claims.varsNum())

	// Just so that there is enough room for gJ to be reused
	maxDegree := claims.degree(0)
	for j := 1; j < claims.varsNum(); j++ {
		if d := claims.degree(j); d > maxDegree {
			maxDegree = d
		}
	}
	gJ := make(polynomial.Polynomial, maxDegree+1) //At the end of iteration j, gJ = ∑_{i < 2ⁿ⁻ʲ⁻¹} g(X₁, ..., Xⱼ₊₁, i...)		NOTE: n is shorthand for claims.varsNum()
	gJR := claims.combinedSum(combinationCoeff)    // At the beginning of iteration j, gJR = ∑_{i < 2ⁿ⁻ʲ} g(r₁, ..., rⱼ, i...)

	for j := range claims.varsNum() {
		if len(proof.partialSumPolys[j]) != claims.degree(j) {
			return errors.New("malformed proof")
		}
		copy(gJ[1:], proof.partialSumPolys[j])
		gJ[0].Sub(&gJR, &proof.partialSumPolys[j][0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)
		// gJ is ready

		//Prepare for the next iteration
		if r[j], err = next(transcript, proof.partialSumPolys[j], &remainingChallengeNames); err != nil {
			return err
		}
		// This is an extremely inefficient way of interpolating. TODO: Interpolate without symbolically computing a polynomial
		gJCoeffs := polynomial.InterpolateOnRange(gJ[:(claims.degree(j) + 1)])
		gJR = gJCoeffs.Eval(&r[j])
	}

	return claims.verifyFinalEval(r, combinationCoeff, gJR, proof.finalEvalProof)
}
