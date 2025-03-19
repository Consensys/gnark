package sha3

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
)

// newHash is a helper function to create a new SHA3 hash.
func newHash(api frontend.API, dsByte byte, rate, outputLen int, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	cfg := new(hash.HasherConfig)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, fmt.Errorf("initializing uints: %w", err)
	}
	return &digest{
		api:           api,
		uapi:          uapi,
		state:         newState(),
		dsbyte:        dsByte,
		rate:          rate,
		outputLen:     outputLen,
		minimalLength: cfg.MinimalLength,
	}, nil
}

// New256 creates a new SHA3-256 hash.
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	return newHash(api, 0x06, 136, 32, opts...)
}

// New384 creates a new SHA3-384 hash.
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
func New384(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	return newHash(api, 0x06, 104, 48, opts...)
}

// New512 creates a new SHA3-512 hash.
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
func New512(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	return newHash(api, 0x06, 72, 64, opts...)
}

// NewLegacyKeccak256 creates a new Keccak-256 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use New256 instead.
func NewLegacyKeccak256(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	return newHash(api, 0x01, 136, 32, opts...)
}

// NewLegacyKeccak512 creates a new Keccak-512 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use New512 instead.
func NewLegacyKeccak512(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	return newHash(api, 0x01, 72, 64, opts...)
}
