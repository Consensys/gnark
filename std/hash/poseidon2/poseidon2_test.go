package poseidon2_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/poseidon2"
	gkr_poseidon2 "github.com/consensys/gnark/std/hash/poseidon2/gkr-poseidon2"
	permutation "github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2"
	"github.com/consensys/gnark/test"
)

type poseidon2Circuit struct {
	Input    []frontend.Variable
	Expected []frontend.Variable `gnark:",public"` // Expected[i] = H(Input[:i+1])
}

func (c *poseidon2Circuit) Define(api frontend.API) error {
	if len(c.Input) != len(c.Expected) {
		return fmt.Errorf("length mismatch")
	}
	hsh, err := poseidon2.New(api)
	if err != nil {
		return err
	}

	compressor, err := permutation.NewCompressor(api)
	if err != nil {
		return err
	}

	gkr, err := gkr_poseidon2.New(api)
	if err != nil {
		return err
	}

	for i := range c.Input {
		hsh.Write(c.Input[i])
		api.AssertIsEqual(c.Expected[i], hsh.Sum())
		gkr.Write(c.Input[i])
		api.AssertIsEqual(c.Expected[i], gkr.Sum())
		api.AssertIsEqual(c.Expected[i], hash.SumMerkleDamgardDynamicLength(api, compressor, 0, i+1, c.Input))
	}
	return nil
}

func TestPoseidon2Hash(t *testing.T) {
	assert := test.NewAssert(t)

	var buf [fr.Bytes]byte
	const nbInputs = 5
	// prepare expected output
	h := poseidonbls12377.NewMerkleDamgardHasher()
	expected := make([]frontend.Variable, nbInputs)
	input := make([]frontend.Variable, nbInputs)
	for i := range input {
		buf[fr.Bytes-1] = byte(i)
		_, err := h.Write(buf[:])
		assert.NoError(err)
		input[i] = i
		expected[i] = h.Sum(nil)
	}

	assert.CheckCircuit(
		&poseidon2Circuit{
			Input:    make([]frontend.Variable, nbInputs),
			Expected: make([]frontend.Variable, nbInputs),
		}, test.WithValidAssignment(&poseidon2Circuit{
			Input:    input,
			Expected: expected,
		}), test.WithCurves(ecc.BLS12_377))
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
