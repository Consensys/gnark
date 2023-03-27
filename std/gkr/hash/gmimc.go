package hash

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GMimcT2 is a hasher for t = 2
var GMimcT2 GMimcHasher

// GMimcT4 is a hasher for t = 4
var GMimcT4 GMimcHasher

// GMimcT8 is a hasher for t = 8
var GMimcT8 GMimcHasher

func initGMimc() {
	GMimcT2 = GMimcHasher{t: 2, nRounds: 91}
	GMimcT4 = GMimcHasher{t: 4, nRounds: 91}
	GMimcT8 = GMimcHasher{t: 8, nRounds: 91}
}

// GMimcHasher contains all the parameters to describe a GMimc function
type GMimcHasher struct {
	t       int // size of Cauchy matrix
	nRounds int // number of rounds of the Mimc hash function
}

// Hash hashes a full message
func (g *GMimcHasher) Hash(msg []fr.Element) fr.Element {
	state := make([]fr.Element, g.t)

	for i := 0; i < len(msg); i += g.t {
		block := make([]fr.Element, g.t)
		if i+g.t >= len(msg) {
			// Only zero-pad the input
			copy(block, msg[i:])
		} else {
			// Take a full chunk
			copy(block, msg[i:i+g.t])
		}
		g.UpdateInplace(state, block)
	}

	return state[0]
}

// UpdateInplace updates the state with the provided block of data
func (g *GMimcHasher) UpdateInplace(state []fr.Element, block []fr.Element) {
	oldState := append([]fr.Element{}, state...)
	for i := 0; i < g.nRounds; i++ {
		AddArkAndKeysInplace(state, block, Arks[i])
		SBoxInplace(&state[0])
		InPlaceCircularPermutation(state)
	}

	// Recombine with the old state
	for i := range state {
		state[i].Add(&state[i], &oldState[i])
		state[i].Add(&state[i], &block[i])
	}
}

// InPlaceCircularPermutation moves all the element to the left and place the first element
// at the end of the state
// ie: [a, b, c, d] -> [b, c, d, a]
func InPlaceCircularPermutation(state []fr.Element) {
	for i := 1; i < len(state); i++ {
		state[i-1], state[i] = state[i], state[i-1]
	}
}
