package solidity

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// BLS12381PairingPrecompile implements the BLS12-381 pairing check precompile (0x0a)
// as specified in EIP-2537.
type BLS12381PairingPrecompile struct{}

// Input length for a single pairing check: 2 * 3 * 64 = 384 bytes
const pairLength = 384

// Run implements the BLS12-381 pairing check precompile
func (b *BLS12381PairingPrecompile) Run(input []byte) ([]byte, error) {
	// Input length must be a multiple of 384 bytes (pairs of G1, G2 points)
	if len(input)%pairLength != 0 {
		return nil, errors.New("invalid input length")
	}

	// If input is empty, return 1 (vacuously true)
	if len(input) == 0 {
		return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, nil
	}

	// Process each pair
	var product bls12381.GT
	product.SetOne()

	for i := 0; i < len(input); i += pairLength {
		pair := input[i : i+pairLength]

		// Parse G1 point (first 128 bytes)
		var g1 bls12381.G1Affine
		if _, err := g1.SetBytes(pair[:128]); err != nil {
			return nil, errors.New("invalid G1 point")
		}

		// Parse G2 point (next 256 bytes)
		var g2 bls12381.G2Affine
		if _, err := g2.SetBytes(pair[128:]); err != nil {
			return nil, errors.New("invalid G2 point")
		}

		// Check if points are in correct subgroup
		if !g1.IsInSubGroup() || !g2.IsInSubGroup() {
			return nil, errors.New("point not in correct subgroup")
		}

		// Calculate pairing and multiply with product
		res, _ := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
		product.Mul(&product, &res)
	}

	// Check if final product equals 1
	if product.IsOne() {
		return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, nil
	}
	return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil
} 
