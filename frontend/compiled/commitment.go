package compiled

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
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
	i.nbPrivateCommitted = removeRedundancy(&committed, nbPublicVariables)
	i.Committed = committed

	commitment, err := compiler.NewHint(bsb22CommitmentComputePlaceholder, 1, i.GetCommittedVariables()...)
	if err != nil {
		return nil, err
	}

	bad := true // TODO: Remove
	if len(commitment) == 1 {
		exp := commitment[0].(LinearExpression)
		if len(exp) == 1 {
			coeffId, _, vis := exp[0].Unpack()
			if coeffId == CoeffIdOne && vis == schema.Internal {
				bad = false
			}
		}
	}
	if bad {
		panic("unexpected variable")
	}

	i.CommitmentIndex = (commitment[0].(LinearExpression))[0].WireID()

	commitmentIndexInCommittedList := binarySearch(committed, i.CommitmentIndex)
	i.CommittedAndCommitment = make([]int, len(committed)+1)
	copy(i.CommittedAndCommitment[:commitmentIndexInCommittedList], committed[:commitmentIndexInCommittedList])
	i.CommittedAndCommitment[commitmentIndexInCommittedList] = i.CommitmentIndex
	copy(i.CommittedAndCommitment[commitmentIndexInCommittedList+1:], committed[commitmentIndexInCommittedList:])

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
