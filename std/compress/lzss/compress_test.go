package lzss

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func testCompressionRoundTrip(t *testing.T, d []byte) {
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: 1,
			NbBytesLength:  1,
			Symbol:         0,
		},
		Log: false,
	}
	c, err := Compress(d, settings)
	require.NoError(t, err)
	dBack, err := Decompress(c, settings)
	require.NoError(t, err)
	require.Equal(t, d, dBack)
}

func Test8Zeros(t *testing.T) {
	testCompressionRoundTrip(t, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func Test300Zeros(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, make([]byte, 300))
}
