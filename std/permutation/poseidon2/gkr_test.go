package poseidon2

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGkrPermutation(t *testing.T) {
	pos2Fr := poseidon2.NewHash(2, rF, rP, seed)
	const n = 2
	var k int64
	ins := make([][2]frontend.Variable, n)
	outs := make([]frontend.Variable, n)
	for i := range n {
		var x [2]fr.Element
		ins[i] = [2]frontend.Variable{k, k + 1}

		x[0].SetInt64(k)
		x[1].SetInt64(k + 1)

		require.NoError(t, pos2Fr.Permutation(x[:]))
		outs[i] = x[1]

		k += 2
	}

	circuit := testGkrPermutationCircuit{
		Ins:  ins,
		Outs: outs,
	}

	AddGkrGatesSolution()

	require.NoError(t, test.IsSolved(&circuit, &circuit, ecc.BLS12_377.ScalarField()))
}

type testGkrPermutationCircuit struct {
	Ins  [][2]frontend.Variable
	Outs []frontend.Variable
}

func (c *testGkrPermutationCircuit) Define(api frontend.API) error {

	pos2 := NewGkrPermutations(api)
	api.AssertIsEqual(len(c.Ins), len(c.Outs))
	for i := range c.Ins {
		api.AssertIsEqual(c.Outs[i], pos2.Permute(c.Ins[i][0], c.Ins[i][1]))
	}

	return nil
}

func BenchmarkPoseidon2Gkr(b *testing.B) {
	// just measure the number of constraints
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &testGkrPermutationCircuit{
		Ins:  make([][2]frontend.Variable, 52000),
		Outs: make([]frontend.Variable, 52000),
	})
	require.NoError(b, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}
