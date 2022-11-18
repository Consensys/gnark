package cs

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

type CommitmentInfo struct {
	Committed       []int // sorted list of id's of committed variables
	CommitmentIndex int
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

// NbPublicCommitted returns the number of public variables committed to, given the number of public variables
// IN THE WITNESS (i.e. not counting the commitment itself)
// nbPublic can also be considered as the index of the commitment itself
func (i *CommitmentInfo) NbPublicCommitted(nbPublic int) int {
	m := binarySearch(i.Committed, nbPublic)

	if i.Committed[m] == nbPublic {
		panic("committing to the commitment?!") // TODO: Remove this check
	}

	return m
}

type CommitmentCounter struct {
	CommitCalls        int
	CommittedVariables int
}

func (c *CommitmentCounter) MarkBoolean(frontend.Variable) {
}

func (c *CommitmentCounter) IsBoolean(frontend.Variable) bool {
	//TODO implement me
	panic("implement me")
}

func (c *CommitmentCounter) Field() *big.Int {
	//TODO implement me
	panic("implement me")
}

func (c *CommitmentCounter) FieldBitLen() int {
	//TODO implement me
	panic("implement me")
}

func (c *CommitmentCounter) Commit(v ...frontend.Variable) frontend.Variable {
	c.CommitCalls++
	c.CommittedVariables += len(v)
	if c.CommitCalls > 1 {
		panic("api.Commit(...) can only be called once")
	}
	return nil
}

func (c *CommitmentCounter) Add(frontend.Variable, frontend.Variable, ...frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Neg(frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Sub(frontend.Variable, frontend.Variable, ...frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Mul(frontend.Variable, frontend.Variable, ...frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) DivUnchecked(frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Div(frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) FromBinary(...frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Xor(frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Or(frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) And(frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Select(frontend.Variable, frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Lookup2(frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) IsZero(frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) Cmp(frontend.Variable, frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) AssertIsEqual(frontend.Variable, frontend.Variable) {
}

func (c *CommitmentCounter) AssertIsDifferent(frontend.Variable, frontend.Variable) {
}

func (c *CommitmentCounter) AssertIsBoolean(frontend.Variable) {
}

func (c *CommitmentCounter) AssertIsLessOrEqual(frontend.Variable, frontend.Variable) {
}

func (c *CommitmentCounter) Println(...frontend.Variable) {
}

func (c *CommitmentCounter) Compiler() frontend.Compiler {
	return c
}

func (c *CommitmentCounter) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	//TODO implement me
	panic("implement me")
}

func (c *CommitmentCounter) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	//TODO implement me
	panic("implement me")
}

func (c *CommitmentCounter) Inverse(frontend.Variable) frontend.Variable {
	return nil
}

func (c *CommitmentCounter) ToBinary(frontend.Variable, ...int) []frontend.Variable {
	return nil
}
