package constraint

import (
	"github.com/consensys/gnark/internal/utils"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

const CommitmentDst = "bsb22-commitment"

type Commitment struct {
	Committed          []int // sorted list of id's of committed variables in groth16. in plonk, list of indexes of constraints defining committed values
	NbPrivateCommitted int
	HintID             solver.HintID // TODO @gbotrel we probably don't need that here
	CommitmentIndex    int           // in groth16, CommitmentIndex is the wire index. in plonk, it's the constraint defining it
}

type Commitments []Commitment

func (i *Commitment) NbPublicCommitted() int {
	return i.NbCommitted() - i.NbPrivateCommitted
}

func (i *Commitment) NbCommitted() int {
	return len(i.Committed)
}

// NewCommitment initialize a Commitment object
//   - committed are the sorted wireID to commit to (without duplicate)
//   - nbPublicCommitted is the number of public inputs among the committed wireIDs
func NewCommitment(committed []int, nbPublicCommitted int) Commitment {
	return Commitment{
		Committed:          committed,
		NbPrivateCommitted: len(committed) - nbPublicCommitted,
	}
}

func SerializeCommitment(privateCommitment []byte, publicCommitted []*big.Int, fieldByteLen int) []byte {

	res := make([]byte, len(privateCommitment)+len(publicCommitted)*fieldByteLen)
	copy(res, privateCommitment)

	offset := len(privateCommitment)
	for _, inJ := range publicCommitted {
		inJ.FillBytes(res[offset : offset+fieldByteLen])
		offset += fieldByteLen
	}

	return res
}

// PrivateToPublicGroth16 returns indexes of variables which are private to the constraint system, but public to Groth16. That is, private committed variables and the commitment itself
// TODO Perhaps move it elsewhere since it's specific to groth16
func (i *Commitment) PrivateToPublicGroth16() []int {
	res := make([]int, i.NbPrivateCommitted+1)
	copy(res, i.PrivateCommitted())
	res[i.NbPrivateCommitted] = i.CommitmentIndex
	return res
}

func (i *Commitment) PrivateCommitted() []int {
	return i.Committed[i.NbPublicCommitted():]
}

func (i *Commitment) PublicCommitted() []int {
	return i.Committed[:i.NbPublicCommitted()]
}

func (c Commitments) CommitmentWireIndexes() []int {
	commitmentWires := make([]int, len(c))
	for i := range c {
		commitmentWires[i] = c[i].CommitmentIndex
	}
	return commitmentWires
}

func (c Commitments) CommitmentsAndPrivateCommittedIndexes() []int {
	nbCommitmentAndPrivCommitted := len(c) // an upper bound
	for i := range c {
		nbCommitmentAndPrivCommitted += c[i].NbPrivateCommitted
	}
	res := make([]int, nbCommitmentAndPrivCommitted)
	offset := 0
	for i := range c {
		copy(res[offset:], c[i].PrivateCommitted())
		offset += c[i].NbPrivateCommitted
		res[offset] = c[i].CommitmentIndex
		offset++
	}
	return res
}

// Interleave returns combined information about the commitments
// nbPrivateCommittedWires doesn't double count because the frontend guarantees that no private wire is committed to more than once
// publicAndCommitmentCommitted returns the index of committed wires that would be hashed, and are indexed from the verifier's point of view
func (c Commitments) Interleave(nbPublicVars int) (nbPrivateCommittedWires int, commitmentWires []int, privateCommitted [][]int, publicAndCommitmentCommitted [][]int) {
	commitmentWires = c.CommitmentWireIndexes()

	privateCommitted = make([][]int, len(c))
	publicAndCommitmentCommitted = make([][]int, len(c))
	for i := range c {
		nonPublicCommitted := c[i].PrivateCommitted()
		privateCommitted[i] = make([]int, 0, len(nonPublicCommitted))
		publicAndCommitmentCommitted[i] = make([]int, c[i].NbPublicCommitted(), len(c[i].Committed))
		copy(publicAndCommitmentCommitted[i], c[i].PublicCommitted())
		for _, j := range nonPublicCommitted {
			if k, found := utils.FindInSlice(commitmentWires, j); found { // if j is a commitment wire
				publicAndCommitmentCommitted[i] = append(publicAndCommitmentCommitted[i], k+nbPublicVars)
			} else {
				privateCommitted[i] = append(privateCommitted[i], j)
			}
		}

		nbPrivateCommittedWires += len(privateCommitted[i])
	}
	return
}

// CommitmentIndexesInCommittedLists returns the indexes of the commitments in the list of committed wires
// note that these are not absolute indexes
func (c Commitments) CommitmentIndexesInCommittedLists() [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0, i)
		for j := 0; j < i; j++ {
			if k, found := utils.FindInSlice(c[i].PrivateCommitted(), c[j].CommitmentIndex); found {
				res[i] = append(res[i], k+c[i].NbPublicCommitted())
			}
		}
	}
	return res
}
