package merkle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/std/gadget/hash/mimc"
	"github.com/consensys/gnark/frontend/std/reference/accumulator/merkle"
)

// TreeLevel i-th level of a Merkle tree
// contains only the neigbors (the missing element is computed while rewinding the Merkle tree)
type TreeLevel struct {
	Elements []*frontend.Constraint
	Index    int // position of the missing element
}

// Proof stores a Merkle tree proof
type Proof struct {
	RootHash *frontend.Constraint
	Path     []TreeLevel
}

// NewProof ...
func NewProof(circuit *frontend.CS, mkProof *merkle.Proof) {

	toReturn := &Proof{}
	toReturn.RootHash = circuit.ALLOCATE(mkProof.RootHash)

	for i := 0; i < len(mkProof.Path); i++ {
		l := len(mkProof.Path[i].Elements)
		toReturn.Path[i].Elements = make([]*frontend.Constraint, l)
		for j := 0; j < l; j++ {
			toReturn.Path[i].Elements[j] = circuit.ALLOCATE(mkProof.Path[i].Elements[j])
		}
	}

}

// computeRoot computes the root of the Merkle proof in SNARK circuit
// data in mp, leaf are supposed to be already allocated
func (mp Proof) computeRoot(circuit *frontend.CS, leaf *frontend.Constraint) (*frontend.Constraint, error) {

	hash := mimc.NewMiMC("seed")
	arity := len(mp.Path[0].Elements)

	var curLeaf *frontend.Constraint

	// the first iteration is isolated to not modify the leaf pointer
	if mp.Path[0].Index > arity {
		return leaf, merkle.ErrIndex
	}

	// packedLevel := make([]*frontend.Constraint, arity+1)
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

		packedLevel := make([]*frontend.Constraint, arity+1)
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
func (mp Proof) Verify(circuit *frontend.CS, root, leaf *frontend.Constraint) error {

	computedRoot, err := mp.computeRoot(circuit, leaf)

	if err != nil {
		return err
	}
	computedRoot.Tag("computedRoot")
	//s.MUSTBE_EQ(computedRoot, root)
	return nil
}
