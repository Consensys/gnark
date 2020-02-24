package merkle

import (
	"github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/cs/std/reference/hash/mimc"
)

// TreeLevel i-th level of a Merkle tree
// contains only the neigbours (the missing element is computed while rewinding the Merkle tree)
type TreeLevel struct {
	Elements []curve.Element
	Index    int // position of the missing element
}

// Proof stores a Merkle tree proof
type Proof struct {
	RootHash curve.Element
	Path     []TreeLevel
}

// Verify ensures leaf is a member of the tree defined by {root, Proof.Path}
func (mp Proof) Verify(root, leaf curve.Element) (bool, error) {
	computedRoot, err := computeRoot(leaf, mp.Path)
	return computedRoot.Equal(&root), err
}

// computes the root of the Merkle proof
func computeRoot(leaf curve.Element, path []TreeLevel) (curve.Element, error) {

	hash := mimc.NewMiMC("seed")

	currentLeaf := leaf
	arity := len(path[0].Elements)

	for _, level := range path {

		if len(level.Elements) != arity {
			return leaf, ErrArity
		}
		if level.Index > arity {
			return leaf, ErrIndex
		}

		packedLevel := make([]curve.Element, arity+1)
		copy(packedLevel[:level.Index], level.Elements[:level.Index])
		packedLevel[level.Index] = currentLeaf
		copy(packedLevel[level.Index+1:], level.Elements[level.Index:])
		currentLeaf = hash.Hash(packedLevel...)

	}

	return currentLeaf, nil
}
