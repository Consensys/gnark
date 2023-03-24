package common

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
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
