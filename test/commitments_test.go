package test

import (
	"github.com/consensys/gnark/backend"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/assert"
)

type noCommitmentCircuit struct {
	X frontend.Variable
}

func (c *noCommitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)
	api.AssertIsEqual(c.X, 1)
	return nil
}

type commitmentCircuit struct {
	Public []frontend.Variable `gnark:",public"`
	X      []frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {

	commitment, err := api.(frontend.Committer).Commit(c.X...)
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

type committedConstantCircuit struct {
	X frontend.Variable
}

func (c *committedConstantCircuit) Define(api frontend.API) error {
	commitment, err := api.(frontend.Committer).Commit(1, c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, c.X)
	return nil
}

type committedPublicCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *committedPublicCircuit) Define(api frontend.API) error {
	commitment, err := api.(frontend.Committer).Commit(c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, c.X)
	return nil
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

type doubleCommitCircuit struct {
	X, Y frontend.Variable
}

func (c *doubleCommitCircuit) Define(api frontend.API) error {
	var c0, c1 frontend.Variable
	var err error
	if c0, err = api.(frontend.Committer).Commit(c.X); err != nil {
		return err
	}
	if c1, err = api.(frontend.Committer).Commit(c.X, c.Y); err != nil {
		return err
	}
	api.AssertIsDifferent(c0, c1)
	return nil
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

type commitUniquenessCircuit struct {
	X []frontend.Variable
}

func (c *commitUniquenessCircuit) Define(api frontend.API) error {
	var err error

	ch := make([]frontend.Variable, len(c.X))
	for i := range c.X {
		if ch[i], err = api.(frontend.Committer).Commit(c.X[i]); err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			api.AssertIsDifferent(ch[i], ch[j])
		}
	}
	return nil
}

func TestCommitUniquenessZerosScs(t *testing.T) { // TODO @Tabaie Randomize Groth16 commitments for real

	w, err := frontend.NewWitness(&commitUniquenessCircuit{[]frontend.Variable{0, 0}}, ecc.BN254.ScalarField())
	assert.NoError(t, err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &commitUniquenessCircuit{[]frontend.Variable{nil, nil}})
	assert.NoError(t, err)

	_, err = ccs.Solve(w)
	assert.NoError(t, err)
}

var commitmentTestCircuits []frontend.Circuit

func init() {
	commitmentTestCircuits = []frontend.Circuit{
		&noCommitmentCircuit{1},
		&commitmentCircuit{X: []frontend.Variable{1}, Public: []frontend.Variable{}},                          // single commitment
		&commitmentCircuit{X: []frontend.Variable{1, 2}, Public: []frontend.Variable{}},                       // two commitments
		&commitmentCircuit{X: []frontend.Variable{1, 2, 3, 4, 5}, Public: []frontend.Variable{}},              // five commitments
		&commitmentCircuit{X: []frontend.Variable{0}, Public: []frontend.Variable{1}},                         // single commitment single public
		&commitmentCircuit{X: []frontend.Variable{0, 1, 2, 3, 4}, Public: []frontend.Variable{1, 2, 3, 4, 5}}, // five commitments five public
		&committedConstantCircuit{1},                             // single committed constant
		&committedPublicCircuit{1},                               // single committed public
		&independentCommitsCircuit{X: []frontend.Variable{1, 1}}, // two independent commitments
		&twoCommitCircuit{X: []frontend.Variable{1, 2}, Y: 3},    // two commitments, second depending on first
		&doubleCommitCircuit{X: 1, Y: 2},                         // double committing to the same variable
	}
}

func TestCommitment(t *testing.T) {
	for _, assignment := range commitmentTestCircuits {
		NewAssert(t).ProverSucceeded(hollow(assignment), assignment, WithBackends(backend.GROTH16, backend.PLONK))
	}
}
