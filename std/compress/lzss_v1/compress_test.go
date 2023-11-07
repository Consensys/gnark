package lzss_v1

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCompressionRoundTrip(t *testing.T, nbBitsAddress uint, d []byte, testCaseName ...string) {
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
			NbBitsAddress: nbBitsAddress,
			NbBitsLength:  8,
		},
		StartAt: 256,
	}
	c, err := Compress(d, settings)

	cBytes := c.Marshal()

	if len(testCaseName) == 1 {
		assert.NoError(t, os.WriteFile("../test_cases/"+testCaseName[0]+"/data.lzssv1", cBytes, 0600))
	}

	//cStream := compress.NewStreamFromBytes(c)
	//cHuff := huffman.Encode(cStream)	TODO Huffman
	fmt.Println("Size Compression ratio:", float64(len(d))/float64(len(cBytes)-1))
	//fmt.Println("Estimated Compression ratio (with Huffman):", float64(8*len(d))/float64(len(cHuff.D)))
	if c.Len() > 1024*8 {
		fmt.Printf("Compressed size: %dKB\n", int(float64(len(cBytes[1:])*100)/1024)/100)
		//fmt.Printf("Compressed size (with Huffman): %dKB\n", int(float64(len(cHuff.D)*100)/8192)/100)
	}
	require.NoError(t, err)

	dBack, err := DecompressPureGo(c, settings)
	require.NoError(t, err)

	/*if len(c) < 1024 {
		printHex(c)
	}*/

	require.Equal(t, d[contextSize:], dBack)

	// store huffman code lengths
	/*lens := huffman.GetCodeLengths(cStream)
	var sbb strings.Builder
	sbb.WriteString("symbol,code-length\n")
	for i := range lens {
		sbb.WriteString(fmt.Sprintf("%d,%d\n", i, lens[i]))
	}
	require.NoError(t, os.WriteFile("huffman.csv", []byte(sbb.String()), 0600))*/
}

func Test8Zeros(t *testing.T) {
	testCompressionRoundTrip(t, 8, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	testCompressionRoundTrip(t, 10, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	testCompressionRoundTrip(t, 16, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func Test300Zeros(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 8, make([]byte, 300))
	testCompressionRoundTrip(t, 10, make([]byte, 300))
	testCompressionRoundTrip(t, 16, make([]byte, 300))
}

func TestNoCompression(t *testing.T) {
	testCompressionRoundTrip(t, 8, []byte{'h', 'i'})
	testCompressionRoundTrip(t, 10, []byte{'h', 'i'})
	testCompressionRoundTrip(t, 16, []byte{'h', 'i'})
}

func Test9E(t *testing.T) {
	testCompressionRoundTrip(t, 8, []byte{1, 1, 1, 1, 2, 1, 1, 1, 1})
	testCompressionRoundTrip(t, 16, []byte{1, 1, 1, 1, 2, 1, 1, 1, 1})
}

func Test8ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 8, append([]byte{1}, make([]byte, 8)...))
	testCompressionRoundTrip(t, 16, append([]byte{1}, make([]byte, 8)...))
}

func Test300ZerosAfterNonzero(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTrip(t, 8, append([]byte{'h', 'i'}, make([]byte, 300)...))
	testCompressionRoundTrip(t, 16, append([]byte{'h', 'i'}, make([]byte, 300)...))
}

func TestRepeatedNonzero(t *testing.T) {
	testCompressionRoundTrip(t, 8, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
	testCompressionRoundTrip(t, 16, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
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
			testCompressionRoundTrip(t, 16, d, folder)
		})
	}
}

func TestLongBackrefBug(t *testing.T) {
	testCompressionRoundTrip(t, 16, nil, "bug")
}
