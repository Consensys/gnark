package gkr_poseidon2

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func TestGkrCompression(t *testing.T) {
	const n = 2
	var k int64
	ins := make([][2]frontend.Variable, n)
	outs := make([]frontend.Variable, n)
	for i := range n {
		var x [2]fr.Element
		ins[i] = [2]frontend.Variable{k, k + 1}

		x[0].SetInt64(k)
		x[1].SetInt64(k + 1)
		y0 := x[1]

		require.NoError(t, bls12377Permutation().Permutation(x[:]))
		x[1].Add(&x[1], &y0)
		outs[i] = x[1]

		k += 2
	}

	circuit := testGkrPermutationCircuit{
		Ins:  ins,
		Outs: outs,
	}

	RegisterGkrSolverOptions(ecc.BLS12_377)

	test.NewAssert(t).CheckCircuit(&testGkrPermutationCircuit{Ins: make([][2]frontend.Variable, len(ins)), Outs: make([]frontend.Variable, len(outs))}, test.WithValidAssignment(&circuit), test.WithCurves(ecc.BLS12_377))
}

type testGkrPermutationCircuit struct {
	Ins  [][2]frontend.Variable
	Outs []frontend.Variable
}

func (c *testGkrPermutationCircuit) Define(api frontend.API) error {

	pos2 := NewGkrCompressions(api)
	api.AssertIsEqual(len(c.Ins), len(c.Outs))
	for i := range c.Ins {
		api.AssertIsEqual(c.Outs[i], pos2.Compress(c.Ins[i][0], c.Ins[i][1]))
	}

	return nil
}

func TestGkrPermutationCompiles(t *testing.T) {
	// just measure the number of constraints
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &testGkrPermutationCircuit{
		Ins:  make([][2]frontend.Variable, 52000),
		Outs: make([]frontend.Variable, 52000),
	})
	require.NoError(t, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}
