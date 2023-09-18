package huffman

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReadBits(t *testing.T) {
	bytes := []byte{0xf2, 0x80, 0x5b}

	r := bitReader{bytes, 0}
	require.Equal(t, uint64(0xf2), r.readBits(8))
	require.Equal(t, []uint64{0x80, 0x5b}, r.readAll(8))

	r = bitReader{bytes, 0}
	require.Equal(t, uint64(0x2), r.readBits(4))
	require.Equal(t, []uint64{0x0f, 0xb8, 0x5}, r.readAll(8))

	r = bitReader{bytes, 0}
	require.Equal(t, uint64(0x12), r.readBits(5))
}

/*func TestEstimateHuffmanGains(t *testing.T) {
	data, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)

	// create frequency table
	weights := make([]int, 1<<huffmanBitGranularity)
	reader := bitReader{data: data}
	dataRealigned := reader.readAll(huffmanBitGranularity)
	for _, c := range dataRealigned {
		weights[c]++
	}

	fmt.Println("weights", weights)
	sizes := CreateTree(weights).GetCodeSizes()
	fmt.Println("sizes", sizes)

	// linear combination
	var sum int
	for i := 0; i < 1<<huffmanBitGranularity; i++ {
		sum += weights[i] * sizes[i]
	}

	fmt.Println("would achieve", 100*sum/(8*len(data)), "% compression")
}

func TestEstimateHuffmanOnZct(t *testing.T) {
	var (
		data, zct []byte
		err       error
	)
	data, err = os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)
	zct, err = os.ReadFile(TestCase + "data.zct")
	fmt.Println("default zct compression rate", 100*len(zct)/len(data), "%")

	granularities := []int{2, 4, 6, 8, 10, 12, 14, 16}
	for _, huffmanBitGranularity = range granularities {
		fmt.Println("\nhuffmanBitGranularity", huffmanBitGranularity)
		fmt.Println("just huffman rate", 100*estimateHuffmanCodeSize(data)/(8*len(data)), "%")
		fmt.Println("huffman on zct rate", 100*estimateHuffmanCodeSize(zct)/(8*len(data)), "%")
	}
}
*/
