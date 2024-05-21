package sha3

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
)

// New256 creates a new SHA3-256 hash.
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256(api frontend.API) (hash.BinaryHasher, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &digest{
		uapi:      uapi,
		state:     newState(),
		dsbyte:    0x06,
		rate:      136,
		outputLen: 32,
	}, nil
}

// New384 creates a new SHA3-384 hash.
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
func New384(api frontend.API) (hash.BinaryHasher, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &digest{
		uapi:      uapi,
		state:     newState(),
		dsbyte:    0x06,
		rate:      104,
		outputLen: 48,
	}, nil
}

// New512 creates a new SHA3-512 hash.
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
func New512(api frontend.API) (hash.BinaryHasher, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &digest{
		uapi:      uapi,
		state:     newState(),
		dsbyte:    0x06,
		rate:      72,
		outputLen: 64,
	}, nil
}

// NewLegacyKeccak256 creates a new Keccak-256 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use New256 instead.
func NewLegacyKeccak256(api frontend.API) (hash.BinaryHasher, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &digest{
		uapi:      uapi,
		state:     newState(),
		dsbyte:    0x01,
		rate:      136,
		outputLen: 32,
	}, nil
}

// NewLegacyKeccak512 creates a new Keccak-512 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use New512 instead.
func NewLegacyKeccak512(api frontend.API) (hash.BinaryHasher, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &digest{
		uapi:      uapi,
		state:     newState(),
		dsbyte:    0x01,
		rate:      72,
		outputLen: 64,
	}, nil
}
