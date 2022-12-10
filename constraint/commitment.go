package constraint

import (
	"math/big"
	"sort"

	"github.com/consensys/gnark/backend/hint"
)

const CommitmentDst = "bsb22-commitment"

type Commitment struct {
	Committed              []int // sorted list of id's of committed variables
	NbPrivateCommitted     int
	HintID                 hint.ID // TODO @gbotrel we probably don't need that here
	CommitmentIndex        int
	CommittedAndCommitment []int // sorted list of id's of committed variables AND the commitment itself
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

func NewCommitment(committed []int, nbPublicVariables int) (Commitment, error) {
	var i Commitment
	sort.Ints(committed)
	removeRedundancy(&committed)
	nbPublicCommitted := binarySearch(committed, nbPublicVariables)
	i.NbPrivateCommitted = len(committed) - nbPublicCommitted

	i.Committed = committed
	return i, nil
}

func (i *Commitment) SerializeCommitment(privateCommitment []byte, publicCommitted []*big.Int, fieldByteLen int) []byte {

	res := make([]byte, len(privateCommitment)+len(publicCommitted)*fieldByteLen)
	copy(res, privateCommitment)

	for j, inJ := range publicCommitted {
		inIBytes := inJ.Bytes()
		slack := fieldByteLen - len(inIBytes)
		copy(res[len(privateCommitment)+slack+j*fieldByteLen:], inIBytes)
	}

	return res
}

// GetPrivateToPublic returns indexes of variables which are private to the constraint system, but public to Groth16. That is, private committed variables and the commitment itself
func (i *Commitment) GetPrivateToPublic() []int {
	return i.CommittedAndCommitment[i.NbPublicCommitted():]
}

func (i *Commitment) GetPrivateCommitted() []int {
	return i.Committed[i.NbPublicCommitted():]
}

func removeRedundancy(sorted *[]int) {
	if len(*sorted) == 0 {
		return
	}

	j := 1
	for i := 1; i < len(*sorted); i++ {
		if currentVal := (*sorted)[i]; currentVal != (*sorted)[i-1] {
			(*sorted)[j] = currentVal
			j++
		}
	}

	*sorted = (*sorted)[:j]
}

func binarySearch(slice []int, v int) int { //different from the standard library binary search in that if v is not found, binarySearch returns where it would have been were it to be inserted
	j, k := 0, len(slice)
	for j < k {
		m := (j + k) / 2
		if sM := slice[m]; sM > v {
			k = m // if j < k then m < k so this advances the loop
		} else if sM < v {
			j = m + 1
		} else {
			return m
		}
	}
	return j
}
