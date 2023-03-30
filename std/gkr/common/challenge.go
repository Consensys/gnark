package common

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
)

// GetChallenge returns a interaction challenge
func GetChallenge(challengeSeed []fr.Element) fr.Element {
	mid := len(challengeSeed) / 2
	challengeSeed0, challengeSeed1 := challengeSeed[:mid], challengeSeed[mid:]
	leftSeed := new(fr.Element).SetZero()
	for i := range challengeSeed0 {
		leftSeed = leftSeed.Add(leftSeed, &challengeSeed0[i])
	}
	rightSeed := new(fr.Element).SetZero()
	for i := range challengeSeed1 {
		rightSeed = rightSeed.Add(rightSeed, &challengeSeed1[i])
	}
	return *poseidon.Poseidon(leftSeed, rightSeed)
}

// GetChallengeByTranscript returns a interaction challenge
func GetChallengeByTranscript(challengeSeed []fr.Element, transcript *fiatshamir.Transcript, challengeName string) fr.Element {
	for _, seed := range challengeSeed {
		seedBz := seed.Bytes()
		transcript.Bind(challengeName, seedBz[:])
	}
	result, err := transcript.ComputeChallenge(challengeName)
	if err != nil {
		panic(err)
	}
	return *new(fr.Element).SetBytes(result)
}
