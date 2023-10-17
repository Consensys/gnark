package huffman

import (
	"github.com/consensys/gnark/std/compress"
	"sort"
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

func GetCodeLengths(in compress.Stream) []int {
	// create frequency table
	frequencies := make([]int, in.NbSymbs)
	for _, c := range in.D {
		frequencies[c]++
	}

	huffmanTree := CreateTree(frequencies)
	return huffmanTree.GetCodeSizes(in.NbSymbs)
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
