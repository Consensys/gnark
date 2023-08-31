package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark/std/compress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func testCompressionRoundTrip(t *testing.T, nbBytesAddress uint, d []byte) {
	var heads []LogHeads
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesAddress,
			NbBytesLength:  1,
			Symbol:         0,
		},
		Log:      false,
		LogHeads: &heads,
	}
	c, err := Compress(d, settings)
	require.NoError(t, err)
	cp, err := DescribeCompressionActions(c, settings)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile("compression-summary.txt", []byte(cp), 0644))
	dBack, err := Decompress(c, settings)
	require.NoError(t, err)
	for i := range d {
		if len(heads) > 1 && i == heads[1].Decompressed {
			heads = heads[1:]
		}
		if d[i] != dBack[i] {
			t.Errorf("d[%d] = 0x%x, dBack[%d] = 0x%x. Failure starts at data index %d and compressed index %d", i, d[i], i, dBack[i], heads[0].Decompressed, heads[0].Compressed)
			t.FailNow()
		}
	}
	require.Equal(t, d, dBack)
	fmt.Println("Size Compression ratio:", float64(len(d))/float64(len(c)))
	fmt.Println("Gas compression ratio:", float64(compress.BytesGasCost(d))/float64(compress.BytesGasCost(c)))
}

func Test8Zeros(t *testing.T) {
	testCompressionRoundTrip(t, 1, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	testCompressionRoundTrip(t, 2, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func Test300Zeros(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 1, make([]byte, 300))
	testCompressionRoundTrip(t, 2, make([]byte, 300))
}

func TestNoCompression(t *testing.T) {
	testCompressionRoundTrip(t, 1, []byte{'h', 'i'})
	testCompressionRoundTrip(t, 2, []byte{'h', 'i'})
}

func Test8ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 1, append([]byte{1}, make([]byte, 8)...))
	testCompressionRoundTrip(t, 2, append([]byte{1}, make([]byte, 8)...))
}

func Test300ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	//testCompressionRoundTrip(t, 1, append([]byte{'h', 'i'}, make([]byte, 300)...))
	testCompressionRoundTrip(t, 2, append([]byte{'h', 'i'}, make([]byte, 300)...))
}

func TestRepeatedNonzero(t *testing.T) {
	testCompressionRoundTrip(t, 1, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
	testCompressionRoundTrip(t, 2, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
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
			testCompressionRoundTrip(t, 2, d)
		})
	}
}
