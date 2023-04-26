package constraint

import (
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

func (i *Commitment) NbPublicCommitted() int {
	return i.NbCommitted() - i.NbPrivateCommitted
}

func (i *Commitment) NbCommitted() int {
	return len(i.Committed)
}

func (i *Commitment) Is() bool {
	return len(i.Committed) != 0
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
	if !i.Is() {
		return nil
	}
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
