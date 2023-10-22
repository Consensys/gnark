package lzss_v1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/huffman"
	"github.com/stretchr/testify/require"
)

func testCompressionRoundTrip(t *testing.T, nbBytesAddress uint, d []byte, testCaseName ...string) {
	if len(testCaseName) > 1 {
		t.Fatal("either 0 or 1 test case name")
	}
	if len(testCaseName) == 1 && d == nil {
		var err error
		d, err = os.ReadFile("../test_cases/" + testCaseName[0] + "/data.bin")
		require.NoError(t, err)
	}
	const contextSize = 256
	d = append(make([]byte, contextSize), d...)
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesAddress,
			NbBytesLength:  1,
		},
		StartAt: 256,
	}
	c, err := Compress(d, settings)
	require.NoError(t, err)

	if len(testCaseName) == 1 {
		assert.NoError(t, os.WriteFile("../test_cases/"+testCaseName[0]+"/data.lzssv1", c.Write(), 600))
	}

	cHuff := huffman.Encode(c)
	fmt.Println("Size Compression ratio:", float64(len(d)-contextSize)/float64(c.Len()))
	fmt.Println("Estimated Compression ratio (with Huffman):", float64(8*(len(d)-contextSize))/float64(len(cHuff.D)))
	if c.Len() > 1024 {
		fmt.Printf("Compressed size: %dKB\n", int(float64(c.Len()*100)/1024)/100)
		fmt.Printf("Compressed size (with Huffman): %dKB\n", int(float64(len(cHuff.D)*100)/8192)/100)
	}

	dBack, err := DecompressPureGo(c, settings)
	require.NoError(t, err)

	assert.Equal(t, len(d)-contextSize, len(dBack))
	for i := range dBack {
		require.Equal(t, d[contextSize+i], dBack[i], i)
	}
	//require.Equal(t, d[contextSize:], dBack)

	// store huffman code lengths
	lens := huffman.GetCodeLengths(c)
	var sbb strings.Builder
	sbb.WriteString("symbol,code-length\n")
	for i := range lens {
		sbb.WriteString(fmt.Sprintf("%d,%d\n", i, lens[i]))
	}
	require.NoError(t, os.WriteFile("huffman.csv", []byte(sbb.String()), 0600))
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

func Test9E(t *testing.T) {
	testCompressionRoundTrip(t, 1, []byte{1, 1, 1, 1, 2, 1, 1, 1, 1})
	testCompressionRoundTrip(t, 2, []byte{1, 1, 1, 1, 2, 1, 1, 1, 1})
}

func Test8ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 1, append([]byte{1}, make([]byte, 8)...))
	testCompressionRoundTrip(t, 2, append([]byte{1}, make([]byte, 8)...))
}

func Test300ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 1, append([]byte{'h', 'i'}, make([]byte, 300)...))
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
		"large",
	}
	for _, folder := range folders {
		d, err := os.ReadFile("../test_cases/" + folder + "/data.bin")
		require.NoError(t, err)
		t.Run(folder, func(t *testing.T) {
			testCompressionRoundTrip(t, 2, d, folder)
		})
	}
}

func TestLongBackrefBug(t *testing.T) {
	testCompressionRoundTrip(t, 2, nil, "bug")
}

func TestAverageBatch(t *testing.T) {
	assert := require.New(t)

	// read "average_block.hex" file
	d, err := os.ReadFile("./average_block.hex")
	assert.NoError(err)

	// convert to bytes
	data, err := hex.DecodeString(string(d))
	assert.NoError(err)

	// test compress round trip with s2, zstd and lzss
	// s2Res, err := compressWithS2(data)
	// assert.NoError(err)

	// zstdRes, err := compressWithZstd(data)
	// assert.NoError(err)

	lzssRes, err := compresslzss_v1(data)
	assert.NoError(err)

	// fmt.Println("s2 compression ratio:", s2Res.ratio)
	// fmt.Println("zstd compression ratio:", zstdRes.ratio)
	fmt.Println("lzss compression ratio:", lzssRes.ratio)

	// assert.Equal(5.241485472387916, lzssRes.ratio, "regression check")

	// // test decompress round trip with s2, zstd and lzss
	// s2Decompressed, err := decompressWithS2(s2Res.compressed)
	// assert.NoError(err)

	// zstdDecompressed, err := decompressWithZstd(zstdRes.compressed)
	// assert.NoError(err)

	lzssDecompressed, err := decompresslzss_v1(lzssRes.compressed)
	assert.NoError(err)

	// assert.True(bytes.Equal(data, s2Decompressed))
	// assert.True(bytes.Equal(data, zstdDecompressed))
	assert.True(bytes.Equal(data, lzssDecompressed))

}

func BenchmarkAverageBatch(b *testing.B) {
	// read the file
	d, err := os.ReadFile("./average_block.hex")
	if err != nil {
		b.Fatal(err)
	}

	// convert to bytes
	data, err := hex.DecodeString(string(d))
	if err != nil {
		b.Fatal(err)
	}

	// benchmark s2
	// b.Run("s2", func(b *testing.B) {
	// 	for i := 0; i < b.N; i++ {
	// 		_, err := compressWithS2(data)
	// 		if err != nil {
	// 			b.Fatal(err)
	// 		}
	// 	}
	// })

	// // benchmark zstd
	// b.Run("zstd", func(b *testing.B) {
	// 	for i := 0; i < b.N; i++ {
	// 		_, err := compressWithZstd(data)
	// 		if err != nil {
	// 			b.Fatal(err)
	// 		}
	// 	}
	// })

	// benchmark lzss
	b.Run("lzss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := compresslzss_v1(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

type compressResult struct {
	compressed compress.Stream
	inputSize  int
	outputSize int
	ratio      float64
}

func decompresslzss_v1(data compress.Stream) ([]byte, error) {
	return DecompressPureGo(data, Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: 2,
			NbBytesLength:  1,
		},
		StartAt: 256,
	})
}

func compresslzss_v1(data []byte) (compressResult, error) {
	const contextSize = 256
	data = append(make([]byte, contextSize), data...)
	c, err := Compress(data, Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: 2,
			NbBytesLength:  1,
		},
		StartAt: 256,
	})
	if err != nil {
		return compressResult{}, err
	}
	return compressResult{
		compressed: c,
		inputSize:  len(data),
		outputSize: c.Len(),
		ratio:      float64(len(data)) / float64(c.Len()),
	}, nil
}
