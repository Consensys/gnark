package gkr_poseidon2

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	_ "github.com/consensys/gnark/std/hash/all"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func gkrCompressionsCircuits(n int) (circuit, assignment testGkrCompressionCircuit) {
	ins := make([][2]frontend.Variable, n)
	for i := range n {
		ins[i] = [2]frontend.Variable{i * 2, i*2 + 1}
	}

	return testGkrCompressionCircuit{
			Ins: make([][2]frontend.Variable, len(ins)),
		}, testGkrCompressionCircuit{
			Ins: ins,
		}
}

func TestGkrCompression(t *testing.T) {
	circuit, assignment := gkrCompressionsCircuits(2)

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

type testGkrCompressionCircuit struct {
	Ins       [][2]frontend.Variable
	skipCheck bool
}

func (c *testGkrCompressionCircuit) Define(api frontend.API) error {

	gkr, err := NewCompressor(api)
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

func TestGkrCompressionCompiles(t *testing.T) {
	// just measure the number of constraints
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &testGkrCompressionCircuit{
		Ins:       make([][2]frontend.Variable, 52000),
		skipCheck: true,
	})
	require.NoError(t, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

func BenchmarkGkrCompressions(b *testing.B) {
	circuit, assignment := gkrCompressionsCircuits(50000)

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	require.NoError(b, err)

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	_, err = cs.Solve(witness)
	require.NoError(b, err)
}

func TestGenerateTable(t *testing.T) {
	var sb strings.Builder
	for n := range 256 {
		if n%16 == 0 {
			sb.WriteString("\"+\n\"")
		}
		b := uint8(n)
		b <<= bits.LeadingZeros8(b)
		b = bits.Reverse8(b)
		sb.WriteString(fmt.Sprintf("\\x%x", b))
	}
	fmt.Println(sb.String())
}
