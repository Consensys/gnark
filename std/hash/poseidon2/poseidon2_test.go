package poseidon2_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/hash/poseidon2"
	gkr_poseidon2 "github.com/consensys/gnark/std/hash/poseidon2/gkr-poseidon2"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

type poseidon2Circuit struct {
	Input    []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *poseidon2Circuit) Define(api frontend.API) error {
	hsh, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	gkr, err := gkr_poseidon2.New(api)
	if err != nil {
		return err
	}
	hsh.Write(c.Input...)
	api.AssertIsEqual(hsh.Sum(), c.Expected)
	gkr.Write(c.Input...)
	api.AssertIsEqual(gkr.Sum(), c.Expected)
	return nil
}

func TestPoseidon2Hash(t *testing.T) {
	assert := test.NewAssert(t)

	const nbInputs = 5
	// prepare expected output
	h := poseidonbls12377.NewMerkleDamgardHasher()
	circInput := make([]frontend.Variable, nbInputs)
	for i := range nbInputs {
		_, err := h.Write([]byte{byte(i)})
		assert.NoError(err)
		circInput[i] = i
	}
	res := h.Sum(nil)
	assert.CheckCircuit(&poseidon2Circuit{Input: make([]frontend.Variable, nbInputs)}, test.WithValidAssignment(&poseidon2Circuit{Input: circInput, Expected: res}), test.WithCurves(ecc.BLS12_377)) // we have parametrized currently only for BLS12-377
}

func TestStateStorer(t *testing.T) {
	assignment := testStateStorerCircuit{
		Input: [][]frontend.Variable{
			{0, 1, 2, 3, 4},
		},
	}

	circuit := testStateStorerCircuit{
		Input: make([][]frontend.Variable, len(assignment.Input)),
	}
	for i := range assignment.Input {
		circuit.Input[i] = make([]frontend.Variable, len(assignment.Input[i]))
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

type testStateStorerCircuit struct {
	Input [][]frontend.Variable
}

func (c *testStateStorerCircuit) Define(api frontend.API) error {
	// hashes the whole input in one go
	hshFull, err := poseidon2.New(api)
	if err != nil {
		return err
	}

	// hashes the input in two parts
	hshPartial, err := poseidon2.New(api)
	if err != nil {
		return err
	}

	for _, input := range c.Input {
		// compute desired output
		hshFull.Reset()
		hshFull.Write(input...)
		digest := hshFull.Sum()

		hshPartial.Reset()
		hshPartial.Write(input[:len(input)/2]...)
		state := hshPartial.State()
		hshPartial.Reset()
		api.AssertIsEqual(hshPartial.State()[0], 0)
		if err = hshPartial.SetState(state); err != nil {
			return err
		}
		hshPartial.Write(input[len(input)/2:]...)
		api.AssertIsEqual(hshPartial.Sum(), digest)
	}
	return nil
}

type merkleTreeCircuit struct {
	Leaves []frontend.Variable
}

func (c *merkleTreeCircuit) Define(api frontend.API) error {
	if len(c.Leaves) == 0 {
		return errors.New("no hashing to do")
	}

	hsh, err := gkr_poseidon2.New(api)
	if err != nil {
		return err
	}

	layer := slices.Clone(c.Leaves)

	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, 0) // pad with zero
		}

		for i := range len(layer) / 2 {
			hsh.Reset()
			hsh.Write(layer[2*i], layer[2*i+1])
			layer[i] = hsh.Sum()
		}

		layer = layer[:len(layer)/2]
	}

	api.AssertIsDifferent(layer[0], 0)
	return nil
}

func BenchmarkGkrPoseidon2(b *testing.B) {
	const size = 1 << 16

	circuit := merkleTreeCircuit{
		Leaves: make([]frontend.Variable, size),
	}
	assignment := merkleTreeCircuit{
		Leaves: make([]frontend.Variable, size),
	}

	for i := range assignment.Leaves {
		assignment.Leaves[i] = i
	}

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(b, err)

	w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_, err = cs.Solve(w)
		require.NoError(b, err)
	}
}
