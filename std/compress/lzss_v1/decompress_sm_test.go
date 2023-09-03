package lzss_v1

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test1ZeroSm(t *testing.T) {
	testCompressionRoundTripSm(t, 1, []byte{0})
	testCompressionRoundTripSm(t, 2, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func Test2ZeroSm(t *testing.T) {
	testCompressionRoundTripSm(t, 1, []byte{0, 0, 0})
	testCompressionRoundTripSm(t, 2, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func Test8ZerosSm(t *testing.T) {
	testCompressionRoundTripSm(t, 1, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	testCompressionRoundTripSm(t, 2, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func testCompressionRoundTripSm(t *testing.T, nbBytesOffset uint, d []byte) {
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesOffset,
			NbBytesLength:  1,
			Symbol:         0,
			ReferenceTo:    false,
			AddressingMode: false,
		},
		Logger:   nil,
		LogHeads: new([]LogHeads),
	}

	c, err := Compress(d, settings)
	c = append(c, make([]byte, 2*len(c))...)
	require.NoError(t, err)
	dBack := make([]byte, len(d)*2)

	T := func(padCoeff int) {
		dLength, err := decompressStateMachine(c, len(c)/3, dBack, settings)
		require.NoError(t, err)
		require.Equal(t, d, dBack[:dLength])
	}

	T(2)
	T(1)
}
