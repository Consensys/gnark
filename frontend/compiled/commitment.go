package compiled

import (
	"bytes"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"sort"
)

const CommitmentDst = "bsb22-commitment"

type CommitmentInfo struct {
	Committed          []int // sorted list of id's of committed variables
	NbPrivateCommitted int
	HintID             hint.ID
	CommitmentIndex    int
}

func (i *CommitmentInfo) Is() bool {
	return len(i.Committed) != 0
}

// Too Java?
func (i *CommitmentInfo) Set(committed []int, commitmentIndex, nbPublicVariables int, hintID hint.ID) {
	sort.Ints(committed)
	i.NbPrivateCommitted = removeRedundancy(&committed, nbPublicVariables)
	i.Committed = committed
	i.HintID = hintID
	i.CommitmentIndex = commitmentIndex
}

func (i *CommitmentInfo) GetCommittedVariables() []frontend.Variable {
	res := make([]frontend.Variable, len(i.Committed))
	for j, J := range i.Committed {
		res[j] = LinearExpression{Pack(J, CoeffIdOne, 0)} //TODO: Make sure fake visibility is okay
	}
	return res
}

func (i *CommitmentInfo) SerializeCommitment(privateCommitment []byte, in []*big.Int, fieldByteLen int) []byte {
	buf := bytes.NewBuffer(privateCommitment)
	inPublic := in[:len(i.Committed)-i.NbPrivateCommitted]
	for _, inI := range inPublic {
		inIBytes := inI.Bytes()
		slack := fieldByteLen - len(inIBytes)
		buf.Write(make([]byte, slack))
		buf.Write(inIBytes)
	}
	return buf.Bytes()
}

func (i *CommitmentInfo) GetPrivateCommitted() []int {
	return i.Committed[len(i.Committed)-i.NbPrivateCommitted:]
}

// removeRedundancy does what its name indicates, and also counts how many unique elements are greater than or equal to the threshold
func removeRedundancy(sorted *[]int, threshold int) (nbGeThreshold int) {
	if len(*sorted) == 0 {
		return
	}

	j := 1
	for i := 1; i < len(*sorted); i++ {
		if currentVal := (*sorted)[i]; currentVal != (*sorted)[i-1] {
			(*sorted)[j] = currentVal
			j++

			if currentVal >= threshold {
				nbGeThreshold++
			}
		}
	}

	*sorted = (*sorted)[:j]
	return
}
