package scs_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
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

type IssueDiv0Circuit struct {
	A1, B1 frontend.Variable
	A2, B2 frontend.Variable
	A3, B3 frontend.Variable
	A4, B4 frontend.Variable

	Res1, Res2, Res3, Res4, Res5, Res6, Res7, Res8 frontend.Variable
}

func (c *IssueDiv0Circuit) Define(api frontend.API) error {
	// case 1
	t1 := api.Add(api.Mul(0, c.A1), api.Mul(4, c.B1), 0)
	t2 := api.Add(api.Mul(0, c.A1), api.Mul(5, c.B1), 0)

	// case 2
	t3 := api.Add(api.Mul(4, c.A2), api.Mul(0, c.B2), 0)
	t4 := api.Add(api.Mul(5, c.A2), api.Mul(0, c.B2), 0)

	// case 3
	t5 := api.Add(api.Mul(0, c.A3), api.Mul(0, c.B3), 0)
	t6 := api.Add(api.Mul(0, c.A3), api.Mul(5, c.B3), 0)

	// case 4
	t7 := api.Add(api.Mul(0, c.A4), api.Mul(0, c.B4), 0)
	t8 := api.Add(api.Mul(5, c.A4), api.Mul(0, c.B4), 0)

	// test solver
	api.AssertIsEqual(t1, c.Res1)
	api.AssertIsEqual(t2, c.Res2)
	api.AssertIsEqual(t3, c.Res3)
	api.AssertIsEqual(t4, c.Res4)
	api.AssertIsEqual(t5, c.Res5)
	api.AssertIsEqual(t6, c.Res6)
	api.AssertIsEqual(t7, c.Res7)
	api.AssertIsEqual(t8, c.Res8)
	return nil
}

func TestExistDiv0(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &IssueDiv0Circuit{})
	assert.NoError(err)
	w, err := frontend.NewWitness(&IssueDiv0Circuit{
		A1: 11, B1: 21,
		A2: 11, B2: 21,
		A3: 11, B3: 21,
		A4: 11, B4: 21,
		Res1: 84, Res2: 105,
		Res3: 44, Res4: 55,
		Res5: 0, Res6: 105,
		Res7: 0, Res8: 55,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	_, err = ccs.Solve(w)
	assert.NoError(err)
}

type IssueDiv0Circuit2 struct {
	A1, B1 frontend.Variable

	Res1, Res2 frontend.Variable
}

func (c *IssueDiv0Circuit2) Define(api frontend.API) error {
	// case 1
	b1 := api.Mul(0, c.A1)
	b2 := api.Mul(4, c.B1)
	t1 := api.Mul(b1, b2)

	b3 := api.Mul(2, c.A1)
	b4 := api.Mul(5, c.B1)
	t2 := api.Mul(b3, b4)

	// test solver
	api.AssertIsEqual(t1, c.Res1)
	api.AssertIsEqual(t2, c.Res2)
	return nil
}

func TestExistDiv02(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &IssueDiv0Circuit2{})
	assert.NoError(err)
	w, err := frontend.NewWitness(&IssueDiv0Circuit2{
		A1: 11, B1: 21,
		Res1: 0, Res2: 2310,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	_, err = ccs.Solve(w)
	assert.NoError(err)
}

type TestZeroMulNoConstraintCircuit struct {
	A, B frontend.Variable
}

func (c *TestZeroMulNoConstraintCircuit) Define(api frontend.API) error {
	// case 1
	t1 := api.Mul(0, c.A)
	t2 := api.Mul(t1, c.B)

	t3 := api.Sub(c.A, c.A)
	t4 := api.Mul(3, t3)

	// test solver
	api.AssertIsEqual(t2, 0)
	api.AssertIsEqual(t4, 0)
	return nil
}

func TestZeroMulNoConstraint(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &TestZeroMulNoConstraintCircuit{})
	assert.NoError(err)
	if ccs.GetNbConstraints() != 0 {
		t.Fatal("expected 0 constraints")
	}
}

type mulAccFastTrackCircuit struct {
	A, B frontend.Variable
	Res  frontend.Variable
}

func (c *mulAccFastTrackCircuit) Define(api frontend.API) error {
	r := api.MulAcc(api.Mul(c.A, 1), c.B, c.A)
	api.AssertIsEqual(r, c.Res)
	return nil
}

func TestMulAccFastTrack(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &mulAccFastTrackCircuit{})
	assert.NoError(err)
	assert.Equal(2, ccs.GetNbConstraints())
	w, err := frontend.NewWitness(&mulAccFastTrackCircuit{
		A: 11, B: 21,
		Res: 242,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	solution, err := ccs.Solve(w)
	assert.NoError(err)
	_ = solution
}

type subSameNoConstraintCircuit struct {
	A frontend.Variable
}

func (c *subSameNoConstraintCircuit) Define(api frontend.API) error {
	r := api.Sub(c.A, c.A)
	api.AssertIsEqual(r, 0)
	return nil
}

func TestSubSameNoConstraint(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &subSameNoConstraintCircuit{})
	assert.NoError(err)
	if ccs.GetNbConstraints() != 0 {
		t.Fatal("expected 0 constraints")
	}
}
