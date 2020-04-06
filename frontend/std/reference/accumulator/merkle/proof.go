package merkle

import (
	"github.com/consensys/gnark/frontend/std/reference/hash/mimc/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

// TreeLevel i-th level of a Merkle tree
// contains only the neigbours (the missing element is computed while rewinding the Merkle tree)
type TreeLevel struct {
	Elements []fr.Element
	Index    int // position of the missing element
}

// Proof stores a Merkle tree proof
type Proof struct {
	RootHash fr.Element
	Path     []TreeLevel
}

// Verify ensures leaf is a member of the tree defined by {root, Proof.Path}
func (mp Proof) Verify(root, leaf fr.Element) (bool, error) {
	computedRoot, err := computeRoot(leaf, mp.Path)
	return computedRoot.Equal(&root), err
}

// computes the root of the Merkle proof
func computeRoot(leaf fr.Element, path []TreeLevel) (fr.Element, error) {

	hash := bn256.NewMiMC("seed")

	currentLeaf := leaf
	arity := len(path[0].Elements)

	for _, level := range path {

		if len(level.Elements) != arity {
			return leaf, ErrArity
		}
		if level.Index > arity {
			return leaf, ErrIndex
		}

		packedLevel := make([]fr.Element, arity+1)
		copy(packedLevel[:level.Index], level.Elements[:level.Index])
		packedLevel[level.Index] = currentLeaf
		copy(packedLevel[level.Index+1:], level.Elements[level.Index:])
		currentLeaf = hash.Hash(packedLevel...)

	}

	return currentLeaf, nil
}
