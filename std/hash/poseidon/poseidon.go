package poseidon

import (
	cs "github.com/consensys/gnark/constraint/lazy"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon/constants"
)

// power 5 as s-box
func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	r := api.Mul(x, x)
	r = api.Mul(r, r)
	return api.Mul(r, x)
}

// MDS matrix multiply mds * state
func mix(api frontend.API, state []frontend.Variable) []frontend.Variable {
	width := len(state)
	index := width - 2
	newState := make([]frontend.Variable, width)

	for i := 0; i < width; i++ {
		acc := frontend.Variable(0)
		for j := 0; j < width; j++ {
			mul := api.Mul(constants.MDS[index][i][j], state[j])
			acc = api.Add(acc, mul)
		}
		newState[i] = acc
	}
	return newState
}

func fullRounds(api frontend.API, state []frontend.Variable, roundCounter *int) []frontend.Variable {
	width := len(state)
	index := width - 2
	rf := constants.RF / 2
	for i := 0; i < rf; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			state[j] = api.Add(state[j], constants.RC[index][*roundCounter])
			*roundCounter += 1
			// Apply full s-box
			state[j] = sbox(api, state[j])
		}
		// Apply mix layer
		state = mix(api, state)
	}
	return state
}

func partialRounds(api frontend.API, state []frontend.Variable, roundCounter *int) []frontend.Variable {
	width := len(state)
	index := width - 2
	for i := 0; i < constants.RP[index]; i++ {
		for j := 0; j < width; j++ {
			// Add round constants
			state[j] = api.Add(state[j], constants.RC[index][*roundCounter])
			*roundCounter += 1
		}
		// Apply single s-box
		state[0] = sbox(api, state[0])
		// Apply mix layer
		state = mix(api, state)
	}
	return state
}

func permutation(api frontend.API, state []frontend.Variable) []frontend.Variable {
	roundCounter := 0
	state = fullRounds(api, state, &roundCounter)
	state = partialRounds(api, state, &roundCounter)
	state = fullRounds(api, state, &roundCounter)
	return state
}

func Poseidon(api frontend.API, input ...frontend.Variable) frontend.Variable {
	inputLength := len(input)
	if inputLength == 0 {
		panic("Not supported input size")
	}

	const maxLength = 16
	state := make([]frontend.Variable, maxLength+1)
	state[0] = frontend.Variable(0)
	startIndex := 0
	lastIndex := 0

	// Make a hash chain of the input if its length > maxLength
	if inputLength > maxLength {
		count := inputLength / maxLength
		for i := 0; i < count; i++ {
			lastIndex = (i + 1) * maxLength
			copy(state[1:], input[startIndex:lastIndex])
			api.RecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state)), false, &state)
			state = permutation(api, state)
			api.RecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state)), true, &state)
			startIndex = lastIndex
		}
	}

	// For the remaining part of the input OR if 1 <= inputLength <= 16
	if lastIndex < inputLength {
		lastIndex = inputLength
		remainigLength := lastIndex - startIndex
		copy(state[1:], input[startIndex:lastIndex])
		input := state[:remainigLength+1]
		api.RecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state[:remainigLength+1])), false, &input)
		state = permutation(api, state[:remainigLength+1])
		api.RecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state[:remainigLength+1])), true, &input)
	}
	// Return first element of capacity
	return state[1]
}
