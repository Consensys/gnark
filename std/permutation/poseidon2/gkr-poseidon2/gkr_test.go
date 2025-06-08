package gkr_poseidon2

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	_ "github.com/consensys/gnark/std/hash/all"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func gkrPermutationsCircuits(n int) (circuit, assignment testGkrPermutationCircuit) {
	ins := make([][2]frontend.Variable, n)
	for i := range n {
		ins[i] = [2]frontend.Variable{i * 2, i*2 + 1}
	}

	return testGkrPermutationCircuit{
			Ins: make([][2]frontend.Variable, len(ins)),
		}, testGkrPermutationCircuit{
			Ins: ins,
		}
}

func TestGkrCompression(t *testing.T) {
	circuit, assignment := gkrPermutationsCircuits(2)

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

type testGkrPermutationCircuit struct {
	Ins       [][2]frontend.Variable
	skipCheck bool
}

func (c *testGkrPermutationCircuit) Define(api frontend.API) error {

	gkr, err := NewGkrPermutations(api)
	if err != nil {
		return err
	}
	pos2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	for i := range c.Ins {
		fromGkr := gkr.Compress(c.Ins[i][0], c.Ins[i][1])
		if !c.skipCheck {
			api.AssertIsEqual(pos2.Compress(c.Ins[i][0], c.Ins[i][1]), fromGkr)
		}
	}

	return nil
}

func TestGkrPermutationCompiles(t *testing.T) {
	// just measure the number of constraints
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &testGkrPermutationCircuit{
		Ins:       make([][2]frontend.Variable, 52000),
		skipCheck: true,
	})
	require.NoError(t, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

func BenchmarkGkrPermutations(b *testing.B) {
	circuit, assignment := gkrPermutationsCircuits(50000)

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(b, err)

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	// cpu profile
	f, err := os.Create("cpu.pprof")
	require.NoError(b, err)
	defer func() {
		require.NoError(b, f.Close())
	}()

	err = pprof.StartCPUProfile(f)
	require.NoError(b, err)
	defer pprof.StopCPUProfile()

	_, err = cs.Solve(witness)
	require.NoError(b, err)
}
