package scs_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
)

type circuitDupAdd struct {
	A, B frontend.Variable
	R    frontend.Variable
}

func (c *circuitDupAdd) Define(api frontend.API) error {

	f := api.Add(c.A, c.B)   // 1 constraint
	f = api.Add(c.A, c.B, f) // 1 constraint
	f = api.Add(c.A, c.B, f) // 1 constraint

	d := api.Add(api.Mul(c.A, 3), api.Mul(3, c.B)) // 3a + 3b --> 3 (a + b) shouldn't add a constraint.
	e := api.Mul(api.Add(c.A, c.B), 3)             // no constraints

	api.AssertIsEqual(f, e)   // 1 constraint
	api.AssertIsEqual(d, f)   // 1 constraint
	api.AssertIsEqual(c.R, e) // 1 constraint

	return nil
}

func TestDuplicateAdd(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitDupAdd{})
	assert.NoError(err)

	assert.Equal(6, ccs.GetNbConstraints(), "comparing expected number of constraints")

	w, err := frontend.NewWitness(&circuitDupAdd{
		A: 13,
		B: 42,
		R: 165,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)

	_, err = ccs.Solve(w)
	assert.NoError(err, "solving failed")
}

type circuitDupMul struct {
	A, B   frontend.Variable
	R1, R2 frontend.Variable
}

func (c *circuitDupMul) Define(api frontend.API) error {

	f := api.Mul(c.A, c.B)   // 1 constraint
	f = api.Mul(c.A, c.B, f) // 1 constraint
	f = api.Mul(c.A, c.B, f) // 1 constraint
	// f == (a*b)**3

	d := api.Mul(api.Mul(c.A, 2), api.Mul(3, c.B)) // no constraints
	e := api.Mul(api.Mul(c.A, c.B), 1)             // no constraints
	e = api.Mul(e, e)                              // e**2 (no constraints)
	e = api.Mul(e, api.Mul(c.A, c.B), 1)           // e**3 (no constraints)

	api.AssertIsEqual(f, e)    // 1 constraint
	api.AssertIsEqual(d, c.R1) // 1 constraint
	api.AssertIsEqual(c.R2, e) // 1 constraint

	return nil
}

func TestDuplicateMul(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitDupMul{})
	assert.NoError(err)

	assert.Equal(6, ccs.GetNbConstraints(), "comparing expected number of constraints")

	w, err := frontend.NewWitness(&circuitDupMul{
		A:  13,
		B:  42,
		R1: (13 * 2) * (42 * 3),
		R2: (13 * 42) * (13 * 42) * (13 * 42),
	}, ecc.BN254.ScalarField())
	assert.NoError(err)

	_, err = ccs.Solve(w)
	assert.NoError(err, "solving failed")
}
