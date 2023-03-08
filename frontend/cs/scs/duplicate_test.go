package scs_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
)

type circuitDupAdd struct {
	A, B frontend.Variable
	R    frontend.Variable
}

func (c *circuitDupAdd) Define(api frontend.API) error {

	f := api.Add(c.A, c.B)
	f = api.Add(c.A, c.B, f)
	f = api.Add(c.A, c.B, f)

	d := api.Add(api.Mul(c.A, 3), api.Mul(3, c.B))
	e := api.Mul(api.Add(c.A, c.B), 3)

	api.AssertIsEqual(f, e)
	api.AssertIsEqual(d, f)
	api.AssertIsEqual(c.R, e)

	return nil
}

func TestDuplicateAdd(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitDupAdd{})
	assert.NoError(err)

	// assert.Equal(8, ccs.GetNbConstraints(), "comparing expected number of constraints")
	constraints, r := ccs.(*cs.SparseR1CS).GetConstraints()
	for _, c := range constraints {
		fmt.Println(c.String(r))
	}
}
