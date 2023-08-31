package lzss

import (
	"github.com/stretchr/testify/require"
	"os"
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

func TestNoCompression(t *testing.T) {
	testCompressionRoundTrip(t, []byte{'h', 'i'})
}

func Test8ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, append([]byte{1}, make([]byte, 8)...))
}

func Test300ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, append([]byte{'h', 'i'}, make([]byte, 300)...))
}

func TestRepeatedNonzero(t *testing.T) {
	testCompressionRoundTrip(t, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
}

func TestCalldata(t *testing.T) {
	t.Parallel()
	folders := []string{
		"3c2943",
	}
	for _, folder := range folders {
		d, err := os.ReadFile("../" + folder + "/data.bin")
		require.NoError(t, err)
		t.Run(folder, func(t *testing.T) {
			testCompressionRoundTrip(t, d)
		})
	}
}
