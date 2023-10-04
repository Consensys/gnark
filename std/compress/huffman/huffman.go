package huffman

import (
	"fmt"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/std/compress"
	"os"
	"sort"
	"strings"
)

// copilot code
type huffmanNode struct {
	weight        int // weight is normally the symbol's frequency
	left          *huffmanNode
	right         *huffmanNode
	symbol        int
	nbDescendents int
}

func CreateTree(weights []int) *huffmanNode {
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

func (node *huffmanNode) GetCodeSizes(NbSymbs int) []int {
	// Create the code sizes
	codeSizes := make([]int, NbSymbs)
	stack := make([]stackElem, 0, NbSymbs)
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

func EstimateHuffmanCodeSize(data compress.Stream) int {
	// create frequency table
	frequencies := make([]int, data.NbSymbs)
	for _, c := range data.D {
		frequencies[c]++
	}

	huffmanTree := CreateTree(frequencies)
	sizes := huffmanTree.GetCodeSizes(data.NbSymbs)

	var logWriter strings.Builder
	logWriter.WriteString("Symbol,Frequency,Percentage,Code Length\n")
	for i := range sizes {
		logWriter.WriteString(fmt.Sprintf("%d,%d,%.2f,%d\n", i, frequencies[i], float64(frequencies[i]*100)/float64(data.Len()), sizes[i]))
	}
	if err := os.WriteFile("huffman.csv", []byte(logWriter.String()), 0644); err != nil {
		panic(err)
	}

	// linear combination
	var sum int
	for i := range frequencies {
		sum += frequencies[i] * sizes[i] // in the code itself
	}

	// estimate the size of the tree
	treeSizeLengthForEachSymbol := data.NbSymbs
	treeSizeListUsedSymbolsBits := huffmanTree.nbDescendents // to represent the tree topology
	for i := range frequencies {
		if frequencies[i] != 0 {
			treeSizeListUsedSymbolsBits += data.NbSymbs // list the used symbols
		}
	}
	treeSize := utils.Min(treeSizeLengthForEachSymbol, (treeSizeListUsedSymbolsBits-1)/8+1)

	fmt.Println("estimated huffman tree size:", treeSize)

	return sum + treeSize
}

func _range(end int) []int {
	out := make([]int, end)
	for i := range out {
		out[i] = i
	}
	return out
}

// Encode encodes the data using Huffman coding, EXTREMELY INEFFICIENTLY
func Encode(in compress.Stream) compress.Stream {
	// create frequency table
	frequencies := make([]int, in.NbSymbs)
	for _, c := range in.D {
		frequencies[c]++
	}

	huffmanTree := CreateTree(frequencies)
	codes := make([][]int, in.NbSymbs)
	huffmanTree.traverse([]int{}, codes)

	// encode
	out := make([]int, 0)
	for _, c := range in.D {
		out = append(out, codes[c]...)
	}
	return compress.Stream{D: out, NbSymbs: 2}
}

func (node *huffmanNode) traverse(code []int, codes [][]int) {
	if node.left == nil && node.right == nil {
		codes[node.symbol] = make([]int, len(code))
		copy(codes[node.symbol], code)
		return
	}
	if node.left != nil {
		node.left.traverse(append(code, 0), codes)
	}
	if node.right != nil {
		node.right.traverse(append(code, 1), codes)
	}
}
