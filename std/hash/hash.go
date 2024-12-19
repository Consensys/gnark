// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package hash provides an interface that hash functions (as gadget) should implement.
package hash

import (
	"errors"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// FieldHasher hashes inputs into a short digest. This interface mocks
// [BinaryHasher], but is more suitable in-circuit by assuming the inputs are
// scalar field elements and outputs digest as a field element. Such hash
// functions are for example Poseidon, MiMC etc.
type FieldHasher interface {
	// Sum computes the hash of the internal state of the hash function.
	Sum() frontend.Variable

	// Write populate the internal state of the hash function with data. The inputs are native field elements.
	Write(data ...frontend.Variable)

	// Reset empty the internal state and put the intermediate state to zero.
	Reset()
}

// StateStorer allows to store and retrieve the state of a hash function.
type StateStorer interface {
	FieldHasher
	// State retrieves the current state of the hash function. Calling this
	// method should not destroy the current state and allow continue the use of
	// the current hasher. The number of returned Variable is implementation
	// dependent.
	State() []frontend.Variable
	// SetState sets the state of the hash function from a previously stored
	// state retrieved using [StateStorer.State] method. The implementation
	// returns an error if the number of supplied Variable does not match the
	// number of Variable expected.
	SetState(state []frontend.Variable) error
}

var (
	builderRegistry = make(map[string]func(api frontend.API) (FieldHasher, error))
	lock            sync.RWMutex
)

func Register(name string, builder func(api frontend.API) (FieldHasher, error)) {
	lock.Lock()
	defer lock.Unlock()
	builderRegistry[name] = builder
}

func GetFieldHasher(name string, api frontend.API) (FieldHasher, error) {
	lock.RLock()
	defer lock.RUnlock()
	builder, ok := builderRegistry[name]
	if !ok {
		return nil, errors.New("hash function not found")
	}
	return builder(api)
}

// BinaryHasher hashes inputs into a short digest. It takes as inputs bytes and
// outputs byte array whose length depends on the underlying hash function. For
// SNARK-native hash functions use [FieldHasher].
type BinaryHasher interface {
	// Sum finalises the current hash and returns the digest.
	Sum() []uints.U8

	// Write writes more bytes into the current hash state.
	Write([]uints.U8)

	// Size returns the number of bytes this hash function returns in a call to
	// [BinaryHasher.Sum].
	Size() int
}

// BinaryFixedLengthHasher is like [BinaryHasher], but assumes the length of the
// input is not full length as defined during compile time. This allows to
// compute digest of variable-length input, unlike [BinaryHasher] which assumes
// the length of the input is the total number of bytes written.
type BinaryFixedLengthHasher interface {
	BinaryHasher
	// FixedLengthSum returns digest of the first length bytes.
	FixedLengthSum(length frontend.Variable) []uints.U8
}
