package constraint

import (
	"github.com/consensys/gnark/constraint/solver"
	"math/big"
)

const CommitmentDst = "bsb22-commitment"

type Groth16Commitment struct {
	PublicAndCommitmentCommitted []int // PublicAndCommitmentCommitted sorted list of id's of public and commitment committed wires
	PrivateCommitted             []int // PrivateCommitted sorted list of id's of private/internal committed wires
	CommitmentIndex              int   // CommitmentIndex the wire index of the commitment
	HintID                       solver.HintID
	NbPublicCommitted            int
}

type PlonkCommitment struct {
	Committed       []int // sorted list of id's of committed variables in groth16. in plonk, list of indexes of constraints defining committed values
	CommitmentIndex int   // CommitmentIndex index of the constraint defining the commitment
	HintID          solver.HintID
}

type Commitment interface{}
type Commitments interface{ CommitmentIndexes() []int }

type Groth16Commitments []Groth16Commitment
type PlonkCommitments []PlonkCommitment

func (c Groth16Commitments) CommitmentIndexes() []int {
	commitmentWires := make([]int, len(c))
	for i := range c {
		commitmentWires[i] = c[i].CommitmentIndex
	}
	return commitmentWires
}

func (c PlonkCommitments) CommitmentIndexes() []int {
	commitmentWires := make([]int, len(c))
	for i := range c {
		commitmentWires[i] = c[i].CommitmentIndex
	}
	return commitmentWires
}

func (c Groth16Commitments) GetPrivateCommitted() [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = c[i].PrivateCommitted
	}
	return res
}

func (c Groth16Commitments) GetPublicCommitted() [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = c[i].PublicAndCommitmentCommitted[:c[i].NbPublicCommitted]
	}
	return res
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

func ToGroth16Commitments(c Commitments) Groth16Commitments {
	if c == nil {
		return nil
	}
	return c.(Groth16Commitments)
}

func ToPlonkCommitments(c Commitments) PlonkCommitments {
	if c == nil {
		return nil
	}
	return c.(PlonkCommitments)
}
