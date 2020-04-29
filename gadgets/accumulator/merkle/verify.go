package merkle

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
)

// nbBits in an Fr element
const nbBits = 256

// leafSum returns the hash created from data inserted to form a leaf. Leaf
// sums are calculated using:
//		Hash(0x00 || data)
func leafSum(circuit *frontend.CS, h mimc.MiMCGadget, data *frontend.Constraint) *frontend.Constraint {

	// TODO find a better way than querying the binary decomposition, too many constraints
	dataBin := circuit.TO_BINARY(data, nbBits)

	// prepending 0x00 means the first chunk to be hashed will consist of the first 31 bytes
	d1 := circuit.FROM_BINARY(dataBin[8:]...)

	// the lsByte of data will become the msByte of the second chunk
	// doing this operation consists in multiplying the lsByte of data by 1 << (31*8)
	// var shifter big.Int
	// shifter.SetString("452312848583266388373324160190187140051835877600158453279131187530910662656", 10) // 1 << (31*8)
	// d2 := circuit.FROM_BINARY(dataBin[:8]...)
	// d2 = circuit.MUL(d2, shifter)

	//res := h.Hash(circuit, d1, d2)
	res := h.Hash(circuit, d1)

	return res
}

// nodeSum returns the hash created from two sibling nodes being combined into
// a parent node. Node sums are calculated using:
//		Hash(0x01 || left sibling sum || right sibling sum)
func nodeSum(circuit *frontend.CS, h mimc.MiMCGadget, a, b *frontend.Constraint) *frontend.Constraint {

	// TODO find a better way than querying the binary decomposition (too many constraints)
	d1Bin := circuit.TO_BINARY(a, nbBits)
	d2Bin := circuit.TO_BINARY(b, nbBits)

	// multiplying by shifter shifts a number by 31*8 bits
	var shifter big.Int
	shifter.SetString("452312848583266388373324160190187140051835877600158453279131187530910662656", 10) // 1 << (31*8)

	// pefix 0x01
	chunk1 := circuit.FROM_BINARY(d1Bin[8:]...)
	chunk1 = circuit.ADD(chunk1, shifter) // adding shifter is equivalent to prefix chunk1 by 0x01

	// lsByte(a)<<31*8 || (b>>8)
	chunk2 := circuit.FROM_BINARY(d1Bin[:8]...) // lsByte(a)
	chunk2 = circuit.MUL(chunk2, shifter)       // chunk2 = lsByte(a)<<31*8
	tmp := circuit.FROM_BINARY(d2Bin[8:]...)
	chunk2 = circuit.ADD(chunk2, tmp) // chunk2 = chunk2 || (b>>8)

	// lsByte(b)<<31*8
	chunk3 := circuit.FROM_BINARY(d2Bin[:8]...)
	chunk3 = circuit.MUL(chunk3, shifter)

	res := h.Hash(circuit, chunk1, chunk2, chunk3)

	return res

}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func VerifyProof(circuit *frontend.CS, h mimc.MiMCGadget, merkleRoot *frontend.Constraint, proofSet []*frontend.Constraint, proofIndex uint64, numLeaves uint64) {

	// In a Merkle tree, every node except the root node has a sibling.
	// Combining the two siblings in the correct order will create the parent
	// node. Each of the remaining hashes in the proof set is a sibling to a
	// node that can be built from all of the previous elements of the proof
	// set. The next node is built by taking:
	//
	//		H(0x01 || sibling A || sibling B)
	//
	// The difficulty of the algorithm lies in determining whether the supplied
	// hash is sibling A or sibling B. This information can be determined by
	// using the proof index and the total number of leaves in the tree.
	//
	// A pair of two siblings forms a subtree. The subtree is complete if it
	// has 1 << height total leaves. When the subtree is complete, the position
	// of the proof index within the subtree can be determined by looking at
	// the bounds of the subtree and determining if the proof index is in the
	// first or second half of the subtree.
	//
	// When the subtree is not complete, either 1 or 0 of the remaining hashes
	// will be sibling B. All remaining hashes after that will be sibling A.
	// This is true because of the way that orphans are merged into the Merkle
	// tree - an orphan at height n is elevated to height n + 1, and only
	// hashed when it is no longer an orphan. Each subtree will therefore merge
	// with at most 1 orphan to the right before becoming an orphan itself.
	// Orphan nodes are always merged with larger subtrees to the left.
	//
	// One vulnerability with the proof verification is that the proofSet may
	// not be long enough. Before looking at an element of proofSet, a check
	// needs to be made that the element exists.

	// The first element of the set is the original data. A sibling at height 1
	// is created by getting the leafSum of the original data.
	height := 0
	// if len(proofSet) <= height {
	// 	return false
	// }
	sum := leafSum(circuit, h, proofSet[height])
	height++

	// While the current subtree (of height 'height') is complete, determine
	// the position of the next sibling using the complete subtree algorithm.
	// 'stableEnd' tells us the ending index of the last full subtree. It gets
	// initialized to 'proofIndex' because the first full subtree was the
	// subtree of height 1, created above (and had an ending index of
	// 'proofIndex').
	stableEnd := proofIndex
	for {
		// Determine if the subtree is complete. This is accomplished by
		// rounding down the proofIndex to the nearest 1 << 'height', adding 1
		// << 'height', and comparing the result to the number of leaves in the
		// Merkle tree.
		subTreeStartIndex := (proofIndex / (1 << uint(height))) * (1 << uint(height)) // round down to the nearest 1 << height
		subTreeEndIndex := subTreeStartIndex + (1 << (uint(height))) - 1              // subtract 1 because the start index is inclusive
		if subTreeEndIndex >= numLeaves {
			// If the Merkle tree does not have a leaf at index
			// 'subTreeEndIndex', then the subtree of the current height is not
			// a complete subtree.
			break
		}
		stableEnd = subTreeEndIndex

		// Determine if the proofIndex is in the first or the second half of
		// the subtree.
		// if len(proofSet) <= height {
		// 	return false
		// }
		if proofIndex-subTreeStartIndex < 1<<uint(height-1) {
			sum = nodeSum(circuit, h, sum, proofSet[height])
		} else {
			sum = nodeSum(circuit, h, proofSet[height], sum)
		}
		height++
	}

	// Determine if the next hash belongs to an orphan that was elevated. This
	// is the case IFF 'stableEnd' (the last index of the largest full subtree)
	// is equal to the number of leaves in the Merkle tree.
	if stableEnd != numLeaves-1 {
		// if len(proofSet) <= height {
		// 	return false
		// }
		sum = nodeSum(circuit, h, sum, proofSet[height])
		height++
	}

	// All remaining elements in the proof set will belong to a left sibling.
	for height < len(proofSet) {
		sum = nodeSum(circuit, h, proofSet[height], sum)
		height++
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	circuit.MUSTBE_EQ(sum, merkleRoot)

}
