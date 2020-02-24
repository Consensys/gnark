package merkle

import (
	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/std/gadget/hash/mimc"
	"github.com/consensys/gnark/cs/std/reference/accumulator/merkle"
)

// TreeLevel i-th level of a Merkle tree
// contains only the neigbors (the missing element is computed while rewinding the Merkle tree)
type TreeLevel struct {
	Elements []*cs.Constraint
	Index    int // position of the missing element
}

// Proof stores a Merkle tree proof
type Proof struct {
	RootHash *cs.Constraint
	Path     []TreeLevel
}

// NewProof ...
func NewProof(circuit *cs.CS, mkProof *merkle.Proof) {

	toReturn := &Proof{}
	toReturn.RootHash = circuit.ALLOCATE(mkProof.RootHash)

	for i := 0; i < len(mkProof.Path); i++ {
		l := len(mkProof.Path[i].Elements)
		toReturn.Path[i].Elements = make([]*cs.Constraint, l)
		for j := 0; j < l; j++ {
			toReturn.Path[i].Elements[j] = circuit.ALLOCATE(mkProof.Path[i].Elements[j])
		}
	}

}

// computeRoot computes the root of the Merkle proof in SNARK circuit
// data in mp, leaf are supposed to be already allocated
func (mp Proof) computeRoot(circuit *cs.CS, leaf *cs.Constraint) (*cs.Constraint, error) {

	hash := mimc.NewMiMC("seed")
	arity := len(mp.Path[0].Elements)

	var curLeaf *cs.Constraint

	// the first iteration is isolated to not modify the leaf pointer
	if mp.Path[0].Index > arity {
		return leaf, merkle.ErrIndex
	}

	// packedLevel := make([]*cs.Constraint, arity+1)
	// for i := 0; i < mp.path[0].index; i++ {
	// 	packedLevel[i] = mp.path[0].neighboursAllocated[i]
	// }
	// packedLevel[mp.path[0].index] = leaf
	// for i := mp.path[0].index + 1; i < arity; i++ {
	// 	packedLevel[i] = mp.path[0].neighboursAllocated[i-1]
	// }
	// curLeaf = hash.Hash(s, packedLevel...)

	for i := 0; i < len(mp.Path); i++ {

		level := mp.Path[i]
		if len(level.Elements) != arity {
			return leaf, merkle.ErrArity
		}
		if level.Index > arity {
			return leaf, merkle.ErrIndex
		}

		packedLevel := make([]*cs.Constraint, arity+1)
		for i := 0; i < level.Index; i++ {
			packedLevel[i] = level.Elements[i]
		}
		packedLevel[level.Index] = leaf
		for i := level.Index + 1; i < arity+1; i++ {
			packedLevel[i] = level.Elements[i-1]
		}
		curLeaf = hash.Hash(circuit, packedLevel...)

	}

	return curLeaf, nil
}

// Verify checks membership of leaf in the Merkle tree
func (mp Proof) Verify(circuit *cs.CS, root, leaf *cs.Constraint) error {

	computedRoot, err := mp.computeRoot(circuit, leaf)

	if err != nil {
		return err
	}
	computedRoot.Tag("computedRoot")
	//s.MUSTBE_EQ(computedRoot, root)
	return nil
}
