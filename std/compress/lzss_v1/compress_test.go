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
		fmt.Printf("Compressed size (with Huffman): %dKB\n", int(float64(len(cHuff.D)*100)/8192)/100)
	}
	require.NoError(t, err)

	dBack, err := DecompressPureGo(c, settings)
	require.NoError(t, err)

	if len(c) < 1024 {
		printHex(c)
	}

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

// Using separate prefix codings for different parts of the data
func TestCalldataMultiHuffman(t *testing.T) {

	d, err := os.ReadFile("../test_cases/large/data.bin")
	require.NoError(t, err)

	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: 2,
			NbBytesLength:  1,
		},
	}
	c, err := Compress(d, settings)
	require.NoError(t, err)
	var cText, cLength, cAddrMs, cAddrLs []byte

	for i := 0; i < len(c); i++ {
		cText = append(cText, c[i])
		if c[i] == 0 {
			cAddrLs = append(cAddrLs, c[i+1])
			cAddrMs = append(cAddrMs, c[i+2])
			cLength = append(cLength, c[i+3])
			i += 3
		}
	}

	cTextStream := compress.NewStreamFromBytes(cText)
	zeroSize := huffman.GetCodeLengths(cTextStream)[0]
	cTextStream = huffman.Encode(cTextStream)

	cLengthStream := huffman.Encode(compress.NewStreamFromBytes(cLength))
	cAddrMsStream := huffman.Encode(compress.NewStreamFromBytes(cAddrMs))
	cAddrLsStream := huffman.Encode(compress.NewStreamFromBytes(cAddrLs))
	huffLen := huffman.Encode(cTextStream).Len() + huffman.Encode(cLengthStream).Len() + huffman.Encode(cAddrMsStream).Len() + huffman.Encode(cAddrLsStream).Len()
	nbBr := nbBackrefs(c)
	brHuffLen := huffLen - cTextStream.Len() + nbBr*zeroSize

	cStream := compress.NewStreamFromBytes(c)
	cHuff := huffman.Encode(cStream)

	fmt.Println("Size Compression ratio:", float64(len(d))/float64(len(c)))
	fmt.Printf("%d%% of total size is backrefs\n", nbBr*400/len(c))

	fmt.Println("Estimated Compression ratio (with vanilla Huffman):", float64(8*len(d))/float64(len(cHuff.D)))

	fmt.Println("Estimated Compression ratio (with Huffman):", float64(8*len(d))/float64(huffLen))

	fmt.Printf("Compressed size: %dKB\n", int(float64(len(c)*100)/1024)/100)
	fmt.Println("Size of backrefs pre Huffman:", nbBr/250, "KB")
	fmt.Printf("Compressed size (with vanilla Huffman): %dKB\n", int(float64(len(cHuff.D)*100)/8192)/100)
	fmt.Printf("Compressed size (with Huffman): %dKB\n", int(float64(huffLen*100)/8192)/100)

	fmt.Printf("Size of backrefs with proper Huffman: %dKB\n", (brHuffLen+8191)/8192)
	fmt.Printf("%d%% of total size is backrefs with proper Huffman\n", brHuffLen*100/huffLen)

	// try huffman on entire br
	cAddrStream := compress.Stream{
		D:       make([]int, len(cAddrLs)),
		NbSymbs: 65536,
	}
	for i := range cAddrLs {
		cAddrStream.D[i] = int(cAddrLs[i]) | (int(cAddrMs[i]) << 8)
	}
	cAddrStream = huffman.Encode(cAddrStream)
	huffLen = huffman.Encode(cTextStream).Len() + huffman.Encode(cLengthStream).Len() + huffman.Encode(cAddrStream).Len()
	brHuffLen = huffLen - cTextStream.Len() + nbBr*zeroSize
	fmt.Println("Estimated Compression ratio (with holistic Huffman):", float64(8*len(d))/float64(huffLen))
	fmt.Printf("Compressed size (with holistic Huffman): %dKB\n", int(float64(huffLen*100)/8192)/100)
	fmt.Printf("Size of backrefs with holistic Huffman: %dKB\n", (brHuffLen+8191)/8192)
	fmt.Printf("%d%% of total size is backrefs with holistic Huffman\n", brHuffLen*100/huffLen)

}

func nbBackrefs(c []byte) int {
	res := 0
	for i := 0; i < len(c); i++ {
		if c[i] == 0 {
			res++
			i += 3
		}
	}
	return res
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
