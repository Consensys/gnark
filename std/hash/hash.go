// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package hash provides an interface that hash functions (as gadget) should implement.
package hash

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
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

	// BlockSize returns the internal block size of the hash function. NB! This
	// is different from [BinaryHasher.Size] which indicates the output size.
	BlockSize() int
}

// BinaryFixedLengthHasher is like [BinaryHasher], but assumes the length of the
// input is not full length as defined during compile time. This allows to
// compute digest of variable-length input, unlike [BinaryHasher] which assumes
// the length of the input is the total number of bytes written.
type BinaryFixedLengthHasher interface {
	BinaryHasher
	// FixedLengthSum returns digest of the first length bytes. See the
	// [WithMinimalLength] option for setting lower bound on length.
	FixedLengthSum(length frontend.Variable) []uints.U8
}

// HasherConfig allows to configure the behavior of the hash constructors. Do
// not initialize the configuration directly but rather use the [Option]
// functions which perform correct initializations. This configuration is
// exported for importing in hash implementations.
type HasherConfig struct {
	MinimalLength int
}

// Option allows configuring the hash functions.
type Option func(*HasherConfig) error

// WithMinimalLength hints the minimal length of the input to the hash function.
// This allows to optimize the constraint count when calling
// [BinaryFixedLengthHasher.FixedLengthSum] as we can avoid selecting between
// the dummy padding and actual padding. If this option is not provided, then we
// assume the minimal length is 0.
func WithMinimalLength(minimalLength int) Option {
	return func(cfg *HasherConfig) error {
		cfg.MinimalLength = minimalLength
		return nil
	}
}

// Compressor is a 2-1 one-way function. It takes two inputs and compresses
// them into one output.
//
// NB! This is lossy compression, meaning that the output is not guaranteed to
// be unique for different inputs. The output is guaranteed to be the same for
// the same inputs.
//
// The Compressor is used in the Merkle-Damgard construction to build a hash
// function.
type Compressor interface {
	Compress(frontend.Variable, frontend.Variable) frontend.Variable
}

type merkleDamgardHasher struct {
	state frontend.Variable
	iv    frontend.Variable
	f     Compressor
	api   frontend.API
}

// NewMerkleDamgardHasher range-extends a 2-1 one-way hash compression function into a hash by way of the Merkle-Damgård construction.
// Parameters:
//   - api: constraint builder
//   - f: 2-1 hash compression (one-way) function
//   - initialState: the initialization vector (IV) in the Merkle-Damgård chain. It must be a value whose preimage is not known.
func NewMerkleDamgardHasher(api frontend.API, f Compressor, initialState frontend.Variable) FieldHasher {
	return &merkleDamgardHasher{
		state: initialState,
		iv:    initialState,
		f:     f,
		api:   api,
	}
}

func (h *merkleDamgardHasher) Reset() {
	h.state = h.iv
}

func (h *merkleDamgardHasher) Write(data ...frontend.Variable) {
	for _, d := range data {
		h.state = h.f.Compress(h.state, d)
	}
}

func (h *merkleDamgardHasher) Sum() frontend.Variable {
	return h.state
}

// SumMerkleDamgardDynamicLength computes the Merkle-Damgård hash of the input data, truncated at the given length.
// Parameters:
//   - api: constraint builder
//   - f: 2-1 hash compression (one-way) function
//   - initialState: the initialization vector (IV) in the Merkle-Damgård chain. It must be a value whose preimage is not known.
//   - length: length of the prefix of data to be hashed. The verifier will not accept a value outside the range {0, 1, ..., len(data)}.
//     The gnark prover will refuse to attempt to generate such an unsuccessful proof.
//   - data: the values a prefix of which is to be hashed.
func SumMerkleDamgardDynamicLength(api frontend.API, f Compressor, initialState frontend.Variable, length frontend.Variable, data []frontend.Variable) frontend.Variable {
	resT := logderivlookup.New(api)
	state := initialState

	resT.Insert(state)
	for _, v := range data {
		state = f.Compress(state, v)
		resT.Insert(state)
	}

	return resT.Lookup(length)[0]
}
