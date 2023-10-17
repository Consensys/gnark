package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/huffman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
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
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesAddress,
			NbBytesLength:  1,
		},
	}
	c, err := Compress(d, settings)
	if len(testCaseName) == 1 {
		assert.NoError(t, os.WriteFile("../test_cases/"+testCaseName[0]+"/data.lzssv1", c, 0600))
	}
	cStream := compress.NewStreamFromBytes(c)
	cHuff := huffman.Encode(cStream)
	fmt.Println("Size Compression ratio:", float64(len(d))/float64(len(c)))
	fmt.Println("Estimated Compression ratio (with Huffman):", float64(8*len(d))/float64(len(cHuff.D)))
	if len(c) > 1024 {
		fmt.Printf("Compressed size: %dKB\n", int(float64(len(c)*100)/1024)/100)
		fmt.Printf("Compressed size (with Huffman): %dKB\n", int(float64(len(cHuff.D)*100)/1024)/100)
	}
	require.NoError(t, err)

	dBack, err := DecompressPureGo(c, settings)
	require.NoError(t, err)

	printHex(c)
	require.Equal(t, d, dBack)

	// store huffman code lengths
	lens := huffman.GetCodeLengths(cStream)
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

func TestCompress26KB(t *testing.T) {
	testCompressionRoundTrip(t, 2, nil, "3c2943")
}

func TestCalldataSymb0(t *testing.T) {
	t.Parallel()
	folders := []string{
		"large",
	}
	for _, folder := range folders {
		d, err := os.ReadFile("../test_cases/" + folder + "/data.bin")
		require.NoError(t, err)
		t.Run(folder, func(t *testing.T) {
			testCompressionRoundTrip(t, 2, d)
		})
	}
}

func TestLongBackrefBug(t *testing.T) {
	testCompressionRoundTrip(t, 2, nil, "bug")
}

func printHex(d []byte) {
	for i := range d {
		if i%32 == 0 {
			fmt.Printf("\n[%d]: ", i)
		}
		s := fmt.Sprintf("%x", d[i])
		if len(s) == 1 {
			s = "0" + s
		}
		fmt.Print(s)
	}
	fmt.Println()
}

func TestDifferentHuffmanTrees(t *testing.T) {
	const folder = "large"
	c, err := os.ReadFile("../test_cases/" + folder + "/data.lzssv1")
	require.NoError(t, err)
	var freqs [4][256]int
	i := 0
	record := func(n int) {
		for j := 0; j < n; j++ {
			freqs[j][c[i+j]]++
		}
		i += n
	}
	for i < len(c) {
		if c[i] == 0 {
			record(4)
		} else {
			record(1)
		}
	}
	total := 0
	for j := 0; j < 4; j++ {
		sizes := huffman.CreateTree(freqs[j][:]).GetCodeSizes(256)
		for k := range sizes {
			total += freqs[j][k] * sizes[k]
		}
	}

	d, err := os.ReadFile("../test_cases/" + folder + "/data.bin")
	require.NoError(t, err)

	fmt.Println("Total bits:", total)
	fmt.Println("Total bytes:", (total+7)/8)
	fmt.Println("Regular huffman compression up to:", float64(8*len(d))/float64(len(huffman.Encode(compress.NewStreamFromBytes(c)).D)))
	fmt.Println("Further compression:", float64(len(c))/float64((total+7)/8))
	fmt.Println("Total compression:", float64(len(d))/float64((total+7)/8))
}
