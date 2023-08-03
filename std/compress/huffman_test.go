package compress

import (
	"fmt"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/stretchr/testify/require"
	"os"
	"sort"
	"testing"
)

var huffmanBitGranularity = 8

// copilot code
type huffmanNode struct {
	weight        int
	left          *huffmanNode
	right         *huffmanNode
	symbol        int
	nbDescendents int
}

func createHuffmanTree(weights []int) *huffmanNode {
	// Create a list of nodes
	nodes := make([]*huffmanNode, len(weights))
	for i := 0; i < len(weights); i++ {
		nodes[i] = &huffmanNode{weight: weights[i], symbol: i, nbDescendents: 1}
	}

	// Create the tree
	for len(nodes) > 1 {
		// Sort the nodes
		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].weight < nodes[j].weight
		})

		// Create a new node
		newNode := &huffmanNode{weight: nodes[0].weight + nodes[1].weight, left: nodes[0], right: nodes[1],
			nbDescendents: nodes[0].nbDescendents + nodes[1].nbDescendents}
		// Remove the first two nodes
		nodes = nodes[2:]

		// Add the new node
		nodes = append(nodes, newNode)
	}

	return nodes[0]
}

type stackElem struct {
	node  *huffmanNode
	depth int
}

type bitReader struct {
	data   []byte
	offset int
}

func (r *bitReader) eof() bool {
	return r.offset >= 8*len(r.data)
}

func (r *bitReader) readAll(n int) []uint64 {
	res := make([]uint64, 0, 1+(len(r.data)*8-r.offset)/n)
	for !r.eof() {
		res = append(res, r.readBits(n))
	}
	return res
}

func (r *bitReader) readBits(n int) uint64 {
	if n >= 64 {
		panic("too many bits")
	}

	res := uint64(0)
	totalBitsRead := 0
	for totalBitsRead < n && r.offset+totalBitsRead < 8*len(r.data) {
		bitIndex := (r.offset + totalBitsRead) % 8
		byteIndex := (r.offset + totalBitsRead) / 8
		maxBit := utils.Min(8, n-totalBitsRead+bitIndex)
		bitsRead := maxBit - bitIndex

		b := r.data[byteIndex]
		b >>= bitIndex
		b &= (1 << uint64(bitsRead)) - 1
		res |= uint64(b) << uint64(totalBitsRead)

		totalBitsRead += bitsRead
	}
	r.offset += totalBitsRead

	return res
}

func (node *huffmanNode) getCodeSizes() []int {
	// Create the code sizes
	codeSizes := make([]int, 1<<huffmanBitGranularity)
	stack := make([]stackElem, 0, 1<<huffmanBitGranularity)
	stack = append(stack, stackElem{node, 0})
	for len(stack) > 0 {
		// pop stack
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e.node.right != nil {
			stack = append(stack, stackElem{e.node.right, e.depth + 1})
		}
		if e.node.left != nil {
			stack = append(stack, stackElem{e.node.left, e.depth + 1})
		}
		if e.node.right == nil && e.node.left == nil {
			codeSizes[e.node.symbol] = e.depth
		}
	}
	return codeSizes
}

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

func estimateHuffmanCodeSize(data []byte) int {
	// create frequency table
	frequencies := make([]int, 1<<huffmanBitGranularity)
	reader := bitReader{data: data}
	dataRealigned := reader.readAll(huffmanBitGranularity)
	for _, c := range dataRealigned {
		frequencies[c]++
	}

	//fmt.Println("frequencies", frequencies)
	huffmanTree := createHuffmanTree(frequencies)
	sizes := huffmanTree.getCodeSizes()
	//fmt.Println("sizes", sizes)

	// linear combination
	var sum int
	for i := 0; i < 1<<huffmanBitGranularity; i++ {
		sum += frequencies[i] * sizes[i] // in the code itself
	}

	// estimate the size of the tree
	treeSizeLengthForEachSymbol := 1 << huffmanBitGranularity
	treeSizeListUsedSymbolsBits := huffmanTree.nbDescendents // to represent the tree topology
	for i := range frequencies {
		if frequencies[i] != 0 {
			treeSizeListUsedSymbolsBits += 1 << huffmanBitGranularity // list the used symbols
		}
	}
	fmt.Println("\testimated listy tree size", (treeSizeListUsedSymbolsBits-1)/8+1)
	treeSize := utils.Min(treeSizeLengthForEachSymbol, (treeSizeListUsedSymbolsBits-1)/8+1)
	fmt.Println("\testimated tree size", treeSize)

	return sum + treeSize
}

func TestEstimateHuffmanGains(t *testing.T) {
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
	sizes := createHuffmanTree(weights).getCodeSizes()
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
