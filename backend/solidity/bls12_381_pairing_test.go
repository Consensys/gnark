package solidity

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/require"
)

func TestBLS12381PairingPrecompile(t *testing.T) {
	precompile := &BLS12381PairingPrecompile{}

	t.Run("empty input", func(t *testing.T) {
		result, err := precompile.Run([]byte{})
		require.NoError(t, err)
		require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, result)
	})

	t.Run("invalid input length", func(t *testing.T) {
		_, err := precompile.Run(make([]byte, 100))
		require.Error(t, err)
	})

	t.Run("valid pairing check", func(t *testing.T) {
		// Generate valid test points
		var g1 bls12381.G1Affine
		var g2 bls12381.G2Affine
		g1.Generator()
		g2.Generator()

		// Serialize points
		g1Bytes := g1.Bytes()
		g2Bytes := g2.Bytes()

		// Combine into input
		input := make([]byte, pairLength)
		copy(input[:128], g1Bytes[:])
		copy(input[128:], g2Bytes[:])

		result, err := precompile.Run(input)
		require.NoError(t, err)
		require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, result)
	})
} 
