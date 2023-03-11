package cmp_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

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

	assert.ProverFailed(&assertIsLessCircuit{}, &assertIsLessCircuit{A: 10, B: 19})
}

func TestIsLess(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 2, B: 5, WantIsLess: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 50, B: 45, WantIsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 30, B: 30, WantIsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -2, B: 5, WantIsLess: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -57, B: -50, WantIsLess: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 0, B: -3, WantIsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -4, B: -4, WantIsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 3, B: 3, WantIsLess: 0})

	// large difference:
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 0, B: 8, WantIsLess: 1})
	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: 8, B: 0, WantIsLess: 0})
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 7, B: 0, WantIsLess: 0})
	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: 0, B: 9, WantIsLess: 1})

	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: -7, B: 2, WantIsLess: 1})

	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: -10, B: -18, WantIsLess: 0})

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
	comparator := cmp.NewComparator(api, big.NewInt(7))
	comparator.AssertIsLess(c.A, c.B)

	return nil
}

type isLessCircuit struct {
	A, B       frontend.Variable
	WantIsLess frontend.Variable
}

func (c *isLessCircuit) Define(api frontend.API) error {
	comparator := cmp.NewComparator(api, big.NewInt(7))
	api.AssertIsEqual(c.WantIsLess, comparator.IsLess(c.A, c.B))

	return nil
}

type minCircuit struct {
	A, B    frontend.Variable
	WantMin frontend.Variable
}

func (c *minCircuit) Define(api frontend.API) error {
	comparator := cmp.NewComparator(api, big.NewInt(15))
	api.AssertIsEqual(c.WantMin, comparator.Min(c.A, c.B))

	return nil
}
