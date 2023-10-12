package scs_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"testing"
)

type isNonZeroCircuit struct {
	X []frontend.Variable
}

func (c *isNonZeroCircuit) Define(api frontend.API) error {
	for i := range c.X {
		//api.Println("i", i, "x", c.X[i], "isNonZero", api.(*scs.Builder).IsNonZero(c.X[i]))
		api.AssertIsEqual(api.(*scs.Builder).IsNonZero(c.X[i]),
			api.Sub(1, api.IsZero(c.X[i])),
		)
	}
	return nil
}

func TestIsNonZero(t *testing.T) {
	assert := test.NewAssert(t)

	cases := []frontend.Variable{-1, 0, 1}
	//cases := []frontend.Variable{1}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &isNonZeroCircuit{make([]frontend.Variable, len(cases))})
	assert.NoError(err)
	w, err := frontend.NewWitness(&isNonZeroCircuit{cases}, ecc.BN254.ScalarField())
	assert.NoError(err)
	solution, err := ccs.Solve(w)
	assert.NoError(err)
	_ = solution
}
