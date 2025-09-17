package gkr_mimc

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func TestGkrMiMC(t *testing.T) {
	lengths := []int{1, 2, 3}
	vals := make([]frontend.Variable, len(lengths)*2)
	for i := range vals {
		vals[i] = i + 1
	}

	for _, length := range lengths[1:2] {
		circuit := &testGkrMiMCCircuit{
			In: make([]frontend.Variable, length*2),
		}
		assignment := &testGkrMiMCCircuit{
			In: slices.Clone(vals[:length*2]),
		}

		test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment))
	}
}

type testGkrMiMCCircuit struct {
	In        []frontend.Variable
	skipCheck bool
}

func (c *testGkrMiMCCircuit) Define(api frontend.API) error {
	gkrmimc, err := New(api)
	if err != nil {
		return err
	}

	plainMiMC, err := mimc.New(api)
	if err != nil {
		return err
	}

	// first check that empty input is handled correctly
	api.AssertIsEqual(gkrmimc.Sum(), plainMiMC.Sum())

	ins := [][]frontend.Variable{c.In[:len(c.In)/2], c.In[len(c.In)/2:]}
	for _, in := range ins {
		gkrmimc.Reset()
		gkrmimc.Write(in...)
		res := gkrmimc.Sum()

		if !c.skipCheck {
			plainMiMC.Reset()
			plainMiMC.Write(in...)
			expected := plainMiMC.Sum()
			api.AssertIsEqual(expected, res)
		}
	}

	return nil
}

func TestGkrMiMCCompiles(t *testing.T) {
	const n = 52000
	circuit := testGkrMiMCCircuit{
		In: make([]frontend.Variable, n),
	}
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit, frontend.WithCapacity(27_000_000))
	require.NoError(t, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

type hashTreeCircuit struct {
	Leaves []frontend.Variable
}

func (c hashTreeCircuit) Define(api frontend.API) error {
	if len(c.Leaves) == 0 {
		return errors.New("no hashing to do")
	}

	hsh, err := New(api)
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

func loadCs(t require.TestingT, filename string, circuit frontend.Circuit) constraint.ConstraintSystem {
	f, err := os.Open(filename)

	if os.IsNotExist(err) {
		// actually compile
		cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
		require.NoError(t, err)
		f, err = os.Create(filename)
		require.NoError(t, err)
		defer f.Close()
		_, err = cs.WriteTo(f)
		require.NoError(t, err)
		return cs
	}

	defer f.Close()
	require.NoError(t, err)

	cs := plonk.NewCS(ecc.BLS12_377)

	_, err = cs.ReadFrom(f)
	require.NoError(t, err)

	return cs
}

func BenchmarkHashTree(b *testing.B) {
	const size = 1 << 15 // about 2 ^ 16 total hashes

	circuit := hashTreeCircuit{
		Leaves: make([]frontend.Variable, size),
	}
	assignment := hashTreeCircuit{
		Leaves: make([]frontend.Variable, size),
	}

	for i := range assignment.Leaves {
		assignment.Leaves[i] = i
	}

	cs := loadCs(b, "gkrmimc_hashtree.cs", &circuit)

	w, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	require.NoError(b, err)

	require.NoError(b, cs.IsSolved(w))
}
