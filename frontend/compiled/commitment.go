package compiled

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"sort"
)

const Dst = "bsb22-commitment"

type Info struct {
	Committed              []int // sorted list of id's of committed variables
	nbPrivateCommitted     int
	HintID                 hint.ID
	CommitmentIndex        int
	CommittedAndCommitment []int // sorted list of id's of committed variables AND the commitment itself
}

func (i *Info) NbPrivateCommitted() int {
	return i.nbPrivateCommitted
}

func (i *Info) NbPublicCommitted() int {
	return i.NbCommitted() - i.NbPrivateCommitted() // hopefully inlined?
}

func (i *Info) NbCommitted() int {
	return len(i.Committed)
}

func (i *Info) Is() bool {
	return len(i.Committed) != 0
}

// Too Java?
func (i *Info) Initialize(committed []int, nbPublicVariables int, compiler frontend.Compiler) (frontend.Variable, error) {

	sort.Ints(committed)
	removeRedundancy(&committed)
	nbPublicCommitted := binarySearch(committed, nbPublicVariables)
	i.nbPrivateCommitted = len(committed) - nbPublicCommitted

	i.Committed = committed

	var commitment frontend.Variable
	if hintOut, err := compiler.NewHint(bsb22CommitmentComputePlaceholder, 1, i.GetCommittedVariables()...); err != nil {
		return nil, err
	} else {
		commitment = hintOut[0]
	}

	i.CommitmentIndex = (commitment.(LinearExpression))[0].WireID()

	i.CommittedAndCommitment = append(committed, i.CommitmentIndex) // TODO: Get rid of this field
	if i.CommitmentIndex <= committed[len(committed)-1] {
		return nil, fmt.Errorf("commitment variable index smaller than some committed variable indices")
	}

	i.HintID = hint.UUID(bsb22CommitmentComputePlaceholder)

	return commitment, nil
}

func bsb22CommitmentComputePlaceholder(*big.Int, []*big.Int, []*big.Int) error {
	return fmt.Errorf("placeholder function: to be replaced by commitment computation")
}

func (i *Info) GetCommittedVariables() []frontend.Variable {
	res := make([]frontend.Variable, len(i.Committed))
	for j, wireIndex := range i.Committed {
		res[j] = LinearExpression{Pack(wireIndex, CoeffIdOne, 0)} //TODO: Make sure fake visibility is okay
	}
	return res
}

func (i *Info) SerializeCommitment(privateCommitment []byte, publicCommitted []*big.Int, fieldByteLen int) []byte {
	buf := bytes.NewBuffer(privateCommitment)
	for _, inI := range publicCommitted {
		inIBytes := inI.Bytes()
		slack := fieldByteLen - len(inIBytes)
		buf.Write(make([]byte, slack))
		buf.Write(inIBytes)
	}
	return buf.Bytes()
}

// GetPrivateToPublic returns indexes of variables which are private to the constraint system, but public to Groth16. That is, private committed variables and the commitment itself
func (i *Info) GetPrivateToPublic() []int {
	return i.CommittedAndCommitment[i.NbPublicCommitted():]
}

func (i *Info) GetPrivateCommitted() []int {
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
	return
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
