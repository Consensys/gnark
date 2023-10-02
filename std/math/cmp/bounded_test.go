package cmp_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestAssertIsLessEq(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: 2, B: 3})
	assert.ProverSucceeded(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: 2, B: 2})
	assert.ProverSucceeded(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: -1, B: -1})
	assert.ProverSucceeded(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: -2, B: -1})

	assert.ProverFailed(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: -1, B: -2})
	assert.ProverFailed(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: 4, B: 3})

	// large difference:
	assert.ProverSucceeded(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: 10, B: 17})

	assert.ProverFailed(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: 10, B: 18})
}

func TestAssertIsLess(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&assertIsLessCircuit{}, &assertIsLessCircuit{A: 2, B: 5})
	assert.ProverSucceeded(&assertIsLessCircuit{}, &assertIsLessCircuit{A: -2, B: 5})
	assert.ProverSucceeded(&assertIsLessCircuit{}, &assertIsLessCircuit{A: -5, B: 0})

	assert.ProverFailed(&assertIsLessCircuit{}, &assertIsLessCircuit{A: 1, B: 0})
	assert.ProverFailed(&assertIsLessCircuit{}, &assertIsLessCircuit{A: 4, B: -3})
	assert.ProverFailed(&assertIsLessCircuit{}, &assertIsLessCircuit{A: -2, B: -8})

	// large difference:
	assert.ProverSucceeded(&assertIsLessCircuit{}, &assertIsLessCircuit{A: 10, B: 18})
	assert.ProverSucceeded(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: -7, B: 0})
	assert.ProverFailed(&assertIsLessCircuit{}, &assertIsLessCircuit{A: 10, B: 19})
	assert.ProverFailed(&assertIsLessEqCircuit{}, &assertIsLessEqCircuit{A: -8, B: 0})
}

func TestIsLess(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -3, B: 4, WantIsLess: 1, WantIsLessEq: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 50, B: 45, WantIsLess: 0, WantIsLessEq: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 30, B: 30, WantIsLess: 0, WantIsLessEq: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -2, B: 5, WantIsLess: 1, WantIsLessEq: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -57, B: -50, WantIsLess: 1, WantIsLessEq: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 0, B: -3, WantIsLess: 0, WantIsLessEq: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -4, B: -4, WantIsLess: 0, WantIsLessEq: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 3, B: 3, WantIsLess: 0, WantIsLessEq: 1})

	// large difference:
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 0, B: 7, WantIsLess: 1, WantIsLessEq: 1})
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 6, B: 0, WantIsLess: 0, WantIsLessEq: 0})
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -16, B: -10, WantIsLess: 1, WantIsLessEq: 1})

	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: 0, B: 9, WantIsLess: 1, WantIsLessEq: 1})
	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: -8, B: 0, WantIsLess: 1, WantIsLessEq: 1})
	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: -10, B: -18, WantIsLess: 0, WantIsLessEq: 0})
}

func TestMin(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 2, B: 5, WantMin: 2})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 4, B: 0, WantMin: 0})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: -2, B: -5, WantMin: -5})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: -2, B: 10, WantMin: -2})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 2, B: 2, WantMin: 2})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: -100, B: -100, WantMin: -100})

	// large difference:
	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 10, B: 25, WantMin: 10})
	assert.ProverFailed(&minCircuit{}, &minCircuit{A: 26, B: 10, WantMin: 10})
	assert.ProverFailed(&minCircuit{}, &minCircuit{A: 10, B: 26, WantMin: 10})

	assert.ProverFailed(&minCircuit{}, &minCircuit{A: -5, B: 11, WantMin: -5})

	assert.ProverFailed(&minCircuit{}, &minCircuit{A: -10, B: -26, WantMin: -26})
}

type assertIsLessCircuit struct {
	A, B frontend.Variable `gnark:",public"`
}

func (c *assertIsLessCircuit) Define(api frontend.API) error {
	comparator := cmp.NewBoundedComparator(api, big.NewInt(7), false)
	comparator.AssertIsLess(c.A, c.B)

	return nil
}

type assertIsLessEqCircuit struct {
	A, B frontend.Variable `gnark:",public"`
}

func (c *assertIsLessEqCircuit) Define(api frontend.API) error {
	comparator := cmp.NewBoundedComparator(api, big.NewInt(7), false)
	comparator.AssertIsLessEq(c.A, c.B)

	return nil
}

type isLessCircuit struct {
	A, B         frontend.Variable
	WantIsLess   frontend.Variable
	WantIsLessEq frontend.Variable
}

func (c *isLessCircuit) Define(api frontend.API) error {
	comparator := cmp.NewBoundedComparator(api, big.NewInt(7), false)
	api.AssertIsEqual(c.WantIsLess, comparator.IsLess(c.A, c.B))
	api.AssertIsEqual(c.WantIsLessEq, comparator.IsLessEq(c.A, c.B))

	return nil
}

type minCircuit struct {
	A, B    frontend.Variable
	WantMin frontend.Variable
}

func (c *minCircuit) Define(api frontend.API) error {
	comparator := cmp.NewBoundedComparator(api, big.NewInt(15), false)
	api.AssertIsEqual(c.WantMin, comparator.Min(c.A, c.B))

	return nil
}
