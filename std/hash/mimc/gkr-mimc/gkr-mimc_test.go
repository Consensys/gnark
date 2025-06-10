package gkr_mimc

import (
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
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

		test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254))
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
			api.AssertIsEqual(res, expected)
		}
	}

	return nil
}
