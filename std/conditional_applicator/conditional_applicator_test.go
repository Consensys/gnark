package conditional_applicator

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCollect(t *testing.T) {
	c := testCollectCircuit{
		C:         []frontend.Variable{1, 0, 1, 1, 0},
		Blocks:    [][]frontend.Variable{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12}, {13, 14, 15}},
		NbNonzero: 3,
	}
	c.Out = [][]frontend.Variable{c.Blocks[0], c.Blocks[2], c.Blocks[3], {0, 0, 0}}
	assert.NoError(t, test.IsSolved(&c, &c, ecc.BN254.ScalarField()))
}

type testCollectCircuit struct {
	C         []frontend.Variable
	Blocks    [][]frontend.Variable
	Out       [][]frontend.Variable
	NbNonzero frontend.Variable
}

func (c *testCollectCircuit) Define(api frontend.API) error {
	out, nbNonZero, err := Collect(api, c.C, len(c.Out), c.Blocks...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(nbNonZero, c.NbNonzero)
	api.AssertIsEqual(len(out), len(c.Out))
	for i := range out {
		api.AssertIsEqual(len(out[i]), len(c.Out[i]))
		for j := range out[i] {
			api.AssertIsEqual(out[i][j], c.Out[i][j])
		}
	}
	return nil
}
