// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package hash provides an interface that hash functions (as gadget) should implement.
package hash

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"math/big"
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
		return nil, fmt.Errorf("hash function \"%s\" not registered", name)
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

// CompressionFunction is a 2 to 1 function
type CompressionFunction interface {
	Compress(frontend.API, frontend.Variable, frontend.Variable) frontend.Variable
}

type MerkleDamgardHasherOption func(*MerkleDamgardHasher)

func WithVarLenCap(cap int) MerkleDamgardHasherOption {
	return func(h *MerkleDamgardHasher) {
		if cap < 0 {
			panic("invalid var len cap")
		}
		h.varLenCap = cap
	}
}

// WithNativeID sets the native hash function required for variable length input
func WithNativeID(id hash.Hash) MerkleDamgardHasherOption {
	return func(h *MerkleDamgardHasher) {
		h.nativeId = id
	}
}

func WithInitialState(iv frontend.Variable) MerkleDamgardHasherOption {
	return func(h *MerkleDamgardHasher) {
		h.iv = iv
	}
}

type MerkleDamgardHasher struct {
	state frontend.Variable
	iv    frontend.Variable
	f     CompressionFunction
	api   frontend.API

	varLenCap int
	varLenIns [][]frontend.Variable
	varLens   []frontend.Variable
	nativeId  hash.Hash
}

// NewMerkleDamgardHasher transforms a 2-1 one-way function into a hash
// initialState is a value whose preimage is not known
func NewMerkleDamgardHasher(api frontend.API, f CompressionFunction, options ...MerkleDamgardHasherOption) *MerkleDamgardHasher {
	res := &MerkleDamgardHasher{
		f:         f,
		api:       api,
		varLenCap: -1,
	}

	for _, opt := range options {
		opt(res)
	}

	if res.iv == nil {
		res.iv = 0
	}
	res.state = res.iv

	api.Compiler().Defer(res.finalizeVarLenHashes)

	return res
}

func (h *MerkleDamgardHasher) Reset() {
	h.state = h.iv
}

func (h *MerkleDamgardHasher) Write(data ...frontend.Variable) {
	for _, d := range data {
		h.state = h.f.Compress(h.api, h.state, d)
	}
}

func (h *MerkleDamgardHasher) Sum() frontend.Variable {
	return h.state
}

// Compress aliases the given compression function
func (h *MerkleDamgardHasher) Compress(left, right frontend.Variable) frontend.Variable {
	return h.f.Compress(h.api, left, right)
}

// SumVariableLength returns Hash(data[:length])
// It does not check that len(data) >= length TODO does it?
func (h *MerkleDamgardHasher) SumVariableLength(data []frontend.Variable, length frontend.Variable) frontend.Variable {
	h.api.AssertIsDifferent(length, 0) // finalizeVarLenHashes cannot handle length 0
	h.varLenIns = append(h.varLenIns, data)
	h.varLens = append(h.varLens, length)
	hashIn := make([]frontend.Variable, 2+len(data))
	hashIn[0] = h.nativeId
	hashIn[1] = length
	copy(hashIn[2:], data)
	res, err := h.api.Compiler().NewHint(hashHint, 1, hashIn)
	if err != nil {
		panic(err)
	}
	return res[0]
}

func (h *MerkleDamgardHasher) finalizeVarLenHashes(api frontend.API) error {
	if api != h.api {
		return fmt.Errorf("api mismatch")
	}
	if len(h.varLenIns) == 0 {
		return nil
	}

	if h.varLenCap == -1 {
		h.varLenCap = 0
		for i := range h.varLenIns {
			h.varLenCap += len(h.varLenIns[i])
		}
	}

	ins := make([]frontend.Variable, h.varLenCap)

	end := frontend.Variable(0)
	ends := logderivlookup.New(api)
	for i := range h.varLens {
		end = api.Add(h.varLens[i], end)
		ends.Insert(end)
	}
	//ends.Insert(api.Mul(2, 1<<63))	// a dummy entry that never ends TODO remove

	var i, j frontend.Variable = 0, 0
	state := h.iv
	for insI := range ins {

		isLastElem := api.IsZero(api.Sub(ends.Lookup(i), j))
	}

}

// hashHint applies the hash encoded by ins[0] to ins[2:2+ins[1]]
func hashHint(mod *big.Int, ins, outs []*big.Int) error {
	if len(ins) < 2 || len(outs) != 1 {
		return errors.New("malformed input/output")
	}
	if !ins[0].IsUint64() {
		return errors.New("hash ID too large")
	}
	hsh := hash.Hash(ins[0].Uint64()).New()
	if !ins[1].IsUint64() {
		return errors.New("length too large")
	}
	for i := range ins[1].Uint64() {
		hsh.Write(outs[2+i].Bytes())
	}
	out := hsh.Sum(nil)
	outs[0].SetBytes(out)
	return nil
}
