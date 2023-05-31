package test

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

type noCommitmentCircuit struct {
	X frontend.Variable
}

func (c *noCommitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)
	api.AssertIsEqual(c.X, 1)
	return nil
}

func TestNoCommitmentCircuit(t *testing.T) {
	testAll(t, &noCommitmentCircuit{1})
}

type commitmentCircuit struct {
	Public []frontend.Variable `gnark:",public"`
	X      []frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {

	commitment, err := tryCommit(api, c.X...)
	if err != nil {
		return err
	}
	sum := frontend.Variable(0)
	for i, x := range c.X {
		sum = api.Add(sum, api.Mul(x, i+1))
	}
	for _, p := range c.Public {
		sum = api.Add(sum, p)
	}
	api.AssertIsDifferent(commitment, sum)
	return nil
}

func TestSingleCommitment(t *testing.T) {
	assignment := &commitmentCircuit{X: []frontend.Variable{1}, Public: []frontend.Variable{}}
	testAll(t, assignment)
}

func TestTwoCommitments(t *testing.T) {
	assignment := &commitmentCircuit{X: []frontend.Variable{1, 2}, Public: []frontend.Variable{}}
	testAll(t, assignment)
}

func TestFiveCommitments(t *testing.T) {
	assignment := &commitmentCircuit{X: []frontend.Variable{1, 2, 3, 4, 5}, Public: []frontend.Variable{}}
	testAll(t, assignment)
}

func TestSingleCommitmentSinglePublic(t *testing.T) {
	assignment := &commitmentCircuit{X: []frontend.Variable{0}, Public: []frontend.Variable{1}}
	testAll(t, assignment)
}

func TestFiveCommitmentsFivePublic(t *testing.T) {
	assignment := &commitmentCircuit{X: []frontend.Variable{0, 1, 2, 3, 4}, Public: []frontend.Variable{1, 2, 3, 4, 5}}
	testAll(t, assignment)
}

type committedConstantCircuit struct {
	X frontend.Variable
}

func (c *committedConstantCircuit) Define(api frontend.API) error {
	commitment, err := tryCommit(api, 1, c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, c.X)
	return nil
}

func TestCommittedConstant(t *testing.T) {
	testAll(t, &committedConstantCircuit{1})
}

type committedPublicCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *committedPublicCircuit) Define(api frontend.API) error {
	commitment, err := tryCommit(api, c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, c.X)
	return nil
}

func TestCommittedPublic(t *testing.T) {
	testAll(t, &committedPublicCircuit{1})
}

type independentCommitsCircuit struct {
	X []frontend.Variable
}

func (c *independentCommitsCircuit) Define(api frontend.API) error {
	committer := api.(frontend.Committer)
	for i := range c.X {
		if ch, err := committer.Commit(c.X[i]); err != nil {
			return err
		} else {
			api.AssertIsDifferent(ch, c.X[i])
		}
	}
	return nil
}

func TestTwoIndependentCommits(t *testing.T) {
	testAll(t, &independentCommitsCircuit{X: []frontend.Variable{1, 1}})
}

type twoCommitCircuit struct {
	X []frontend.Variable
	Y frontend.Variable
}

func (c *twoCommitCircuit) Define(api frontend.API) error {
	c0, err := api.(frontend.Committer).Commit(c.X...)
	if err != nil {
		return err
	}
	var c1 frontend.Variable
	if c1, err = api.(frontend.Committer).Commit(c0, c.Y); err != nil {
		return err
	}
	api.AssertIsDifferent(c1, c.Y)
	return nil
}

func TestTwoCommit(t *testing.T) {
	testAll(t, &twoCommitCircuit{X: []frontend.Variable{1, 2}, Y: 3})
}

func TestHollow(t *testing.T) {

	run := func(c, expected frontend.Circuit) func(t *testing.T) {
		return func(t *testing.T) {
			seen := hollow(c)
			assert.Equal(t, expected, seen)
		}
	}

	assignments := []frontend.Circuit{
		&committedConstantCircuit{1},
		&commitmentCircuit{X: []frontend.Variable{1}, Public: []frontend.Variable{}},
	}

	expected := []frontend.Circuit{
		&committedConstantCircuit{nil},
		&commitmentCircuit{X: []frontend.Variable{nil}, Public: []frontend.Variable{}},
	}

	for i := range assignments {
		t.Run(removePackageName(reflect.TypeOf(assignments[i]).String()), run(assignments[i], expected[i]))
	}
}

func tryCommit(api frontend.API, x ...frontend.Variable) (frontend.Variable, error) {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return nil, fmt.Errorf("type %T doesn't impl the Committer interface", api)
	}
	return committer.Commit(x...)
}
