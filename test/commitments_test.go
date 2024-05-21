package test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/consensys/gnark/backend"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"

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
	t.Parallel()
	assert := NewAssert(t)

	for i, assignment := range commitmentTestCircuits {
		assert.Run(func(assert *Assert) {
			assert.CheckCircuit(hollow(assignment), WithValidAssignment(assignment), WithBackends(backend.GROTH16, backend.PLONK))
		}, fmt.Sprintf("%d-%s", i, removePackageName(reflect.TypeOf(assignment).String())))
	}
}

func TestCommitmentDummySetup(t *testing.T) {
	t.Parallel()

	run := func(assignment frontend.Circuit) func(t *testing.T) {
		return func(t *testing.T) {
			// just test the prover
			_cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, hollow(assignment))
			require.NoError(t, err)
			_r1cs := _cs.(*cs.R1CS)
			var (
				dPk, pk groth16.ProvingKey
				vk      groth16.VerifyingKey
				w       witness.Witness
			)
			require.NoError(t, groth16.Setup(_r1cs, &pk, &vk))
			require.NoError(t, groth16.DummySetup(_r1cs, &dPk))

			comparePkSizes(t, dPk, pk)

			w, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			require.NoError(t, err)
			_, err = groth16.Prove(_r1cs, &pk, w)
			require.NoError(t, err)
		}
	}

	for _, assignment := range commitmentTestCircuits {
		name := removePackageName(reflect.TypeOf(assignment).String())
		if c, ok := assignment.(*commitmentCircuit); ok {
			name += fmt.Sprintf(":%dprivate %dpublic", len(c.X), len(c.Public))
		}
		t.Run(name, run(assignment))
	}
}

func comparePkSizes(t *testing.T, pk1, pk2 groth16.ProvingKey) {
	// skipping the domain
	require.Equal(t, len(pk1.G1.A), len(pk2.G1.A))
	require.Equal(t, len(pk1.G1.B), len(pk2.G1.B))
	require.Equal(t, len(pk1.G1.Z), len(pk2.G1.Z))
	require.Equal(t, len(pk1.G1.K), len(pk2.G1.K))

	require.Equal(t, len(pk1.G2.B), len(pk2.G2.B))

	require.Equal(t, len(pk1.InfinityA), len(pk2.InfinityA))
	require.Equal(t, len(pk1.InfinityB), len(pk2.InfinityB))
	require.Equal(t, pk1.NbInfinityA, pk2.NbInfinityA)
	require.Equal(t, pk1.NbInfinityB, pk2.NbInfinityB)

	require.Equal(t, len(pk1.CommitmentKeys), len(pk2.CommitmentKeys)) // TODO @Tabaie Compare the commitment keys
}
