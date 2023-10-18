package lzss_v1

import (
	"encoding/hex"
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

func TestLongBackrefBug(t *testing.T) {
	testCompressionRoundTrip(t, 2, nil, "bug")
}

func TestCompressWithContext(t *testing.T) {

	d, err := os.ReadFile("../test_cases/large/data.bin")
	assert.NoError(t, err)
	context, err := os.ReadFile("../test_cases/large/neg-table.bin")
	assert.NoError(t, err)
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: 2,
			NbBytesLength:  1,
		},
		StartAt: uint(len(context)),
	}

	D := make([]byte, len(d)+len(context))
	copy(D, context)
	copy(D[len(context):], d)

	c, err := Compress(D, settings)
	require.NoError(t, err)

	cStream := compress.NewStreamFromBytes(c)
	cHuff := huffman.Encode(cStream)
	fmt.Println("Size Compression ratio:", float64(len(d))/float64(len(c)))
	nbBr := nbBackrefs(c)
	fmt.Printf("Backreferences comprise %d KB, %d%% of total siz\ne", nbBr/250, 400*nbBr/len(c))

	fmt.Println("Estimated Compression ratio (with Huffman):", float64(8*len(d))/float64(len(cHuff.D)))
	if len(c) > 1024 {
		fmt.Printf("Compressed size: %dKB\n", int(float64(len(c)*100)/1024)/100)
		fmt.Printf("Compressed size (with Huffman): %dKB\n", int(float64(len(cHuff.D)*100)/8192)/100)
	}

	references, _ := usageStatistics(c)
	var unused []int
	for i := 0; i < len(context); i++ {
		if references[i] == 0 {
			unused = append(unused, i)
		}
	}
	fmt.Println(len(unused), "unused bytes in context", unused)
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

func usageStatistics(c []byte) (references []int, isReference []bool) {

	dI := 0
	for cI := 0; cI < len(c); cI++ {
		if c[cI] == 0 {
			offset := (int(c[cI+1]) | (int(c[cI+2]) << 8)) + 1
			length := int(c[cI+3]) + 1

			for end := dI + length; dI < end; dI++ {
				isReference = append(isReference, true)
				references = append(references, 0)
				if dI-offset >= 0 {
					references[dI-offset]++
				}
			}
			cI += 3
		} else {
			references = append(references, 0)
			isReference = append(isReference, false)
			dI++
		}
	}
	return
}

func TestFindUncoveredButReferredTo(t *testing.T) {
	d, err := os.ReadFile("../test_cases/large/data.bin")
	require.NoError(t, err)
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: 2,
			NbBytesLength:  1,
		},
	}
	c, err := Compress(d, settings)

	out := make([]byte, 256)

	references, isReference := usageStatistics(c)

	totalLen := 0
	start := 0
	for i := range d {
		if isReference[i] || references[i] == 0 {
			// flush
			if i-start >= 4 {
				fmt.Println(hex.EncodeToString(d[start:i]))
				fmt.Println("number of references", references[start:i])
				out = append(out, d[start:i]...)
				totalLen += i - start
			}

			start = i + 1
		}
	}
	fmt.Println("totalLen", totalLen, "bytes")
	assert.NoError(t, os.WriteFile("../test_cases/large/neg-table.bin", out, 0600))
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
