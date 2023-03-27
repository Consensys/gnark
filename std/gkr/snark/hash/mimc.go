package hash

import (
	"github.com/consensys/gnark/std/gkr/hash"

	"github.com/consensys/gnark/frontend"
)

// MimcHash returns the result of the hashing function
func MimcHash(cs frontend.API, stream ...frontend.Variable) frontend.Variable {
	state := frontend.Variable(0)
	for _, m := range stream {
		newM := m
		for i := 0; i < hash.MimcRoundsShort; i++ {
			newM = cs.Add(newM, state)
			newM = cs.Add(newM, hash.Arks[i])
			// Raise to the power 7
			tmp := cs.Mul(newM, newM) // ^2
			tmp = cs.Mul(newM, tmp)   // ^3
			tmp = cs.Mul(tmp, tmp)    // ^6
			newM = cs.Mul(newM, tmp)  // ^7
		}
		state = cs.Add(state, newM, state, m)
	}
	return state
}
