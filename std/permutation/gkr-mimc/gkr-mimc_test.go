package gkr_mimc

import (
	"errors"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
)

type merkleTreeCircuit struct {
	Leaves []frontend.Variable
}

func (c merkleTreeCircuit) Define(api frontend.API) error {
	if len(c.Leaves) == 0 {
		return errors.New("no hashing to do")
	}

	hsh, err := NewCompressor(api)
	if err != nil {
		return err
	}

	layer := slices.Clone(c.Leaves)

	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, 0) // pad with zero
		}

		for i := range len(layer) / 2 {
			layer[i] = hsh.Compress(layer[2*i], layer[2*i+1])
		}

		layer = layer[:len(layer)/2]
	}

	api.AssertIsDifferent(layer[0], 0)
	return nil
}

func BenchmarkMerkleTree(b *testing.B) {
	circuit, assignment := hashTreeCircuits(50000)

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(b, err)

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	_, err = cs.Solve(witness)
	require.NoError(b, err)
}

func hashTreeCircuits(n int) (circuit, assignment merkleTreeCircuit) {
	leaves := make([]frontend.Variable, n)
	for i := range n {
		leaves[i] = i
	}

	return merkleTreeCircuit{
			Leaves: make([]frontend.Variable, len(leaves)),
		}, merkleTreeCircuit{
			Leaves: leaves,
		}
}
