// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package hash provides an interface that hash functions (as gadget) should implement.
package hash

import (
	"errors"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	cryptoHash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/hash/mimc"
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
	builderRegistry = make(map[Hash]func(api frontend.API) (FieldHasher, error))
	lock            sync.RWMutex
)

type Hash uint

const (
	// MIMC_NATIVE is the MiMC hash function defined over the native field of
	// the curve (determined at circuit compile time).
	MIMC_NATIVE Hash = iota

	maxHash // maxHash is the number of hash functions registered
)

func (m Hash) New(api frontend.API) (FieldHasher, error) {
	if m < maxHash {
		f := builderRegistry[m]
		if f != nil {
			return f(api)
		}
	}
	return nil, fmt.Errorf("hash function %d not found", m)
}

func (m Hash) String() string {
	switch m {
	case MIMC_NATIVE:
		return "MIMC_NATIVE"
	default:
		return fmt.Sprintf("hash(%d)", m)
	}
}

func (m Hash) Available() bool {
	return m < maxHash && builderRegistry[m] != nil
}

func (m Hash) CryptoHash(api frontend.API) (cryptoHash.Hash, error) {
	switch m {
	case MIMC_NATIVE:
		switch utils.FieldToCurve(api.Compiler().Field()) {
		case ecc.BN254:
			return cryptoHash.MIMC_BN254, nil
		case ecc.BLS12_381:
			return cryptoHash.MIMC_BLS12_381, nil
		case ecc.BLS12_377:
			return cryptoHash.MIMC_BLS12_377, nil
		case ecc.BW6_761:
			return cryptoHash.MIMC_BW6_761, nil
		case ecc.BLS24_315:
			return cryptoHash.MIMC_BLS24_315, nil
		case ecc.BLS24_317:
			return cryptoHash.MIMC_BLS24_317, nil
		case ecc.BW6_633:
			return cryptoHash.MIMC_BW6_633, nil
		}
	}
	return 0, errors.New("hash function not found")
}

func init() {
	Register(MIMC_NATIVE, func(api frontend.API) (FieldHasher, error) {
		h, err := mimc.NewMiMC(api)
		return &h, err
	})
}

func Register(hash Hash, builder func(api frontend.API) (FieldHasher, error)) {
	lock.Lock()
	defer lock.Unlock()
	builderRegistry[hash] = builder
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
