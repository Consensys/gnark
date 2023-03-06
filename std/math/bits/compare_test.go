package bits_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestIsLess(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 2, B: 5, IsLess: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 50, B: 45, IsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 30, B: 30, IsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -2, B: 5, IsLess: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -57, B: -50, IsLess: 1})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 0, B: -3, IsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: -4, B: -4, IsLess: 0})

	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 3, B: 3, IsLess: 0})

	// large difference:
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 0, B: 8, IsLess: 1})
	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: 8, B: 0, IsLess: 0})
	assert.ProverSucceeded(&isLessCircuit{}, &isLessCircuit{A: 7, B: 0, IsLess: 0})
	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: 0, B: 9, IsLess: 1})

	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: -7, B: 2, IsLess: 1})

	assert.ProverFailed(&isLessCircuit{}, &isLessCircuit{A: -10, B: -18, IsLess: 0})

}

func TestMin(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 2, B: 5, Min: 2})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 4, B: 0, Min: 0})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: -2, B: -5, Min: -5})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: -2, B: 10, Min: -2})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 2, B: 2, Min: 2})

	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: -100, B: -100, Min: -100})

	// large difference:
	assert.ProverSucceeded(&minCircuit{}, &minCircuit{A: 10, B: 25, Min: 10})
	assert.ProverFailed(&minCircuit{}, &minCircuit{A: 26, B: 10, Min: 10})
	assert.ProverFailed(&minCircuit{}, &minCircuit{A: 10, B: 26, Min: 10})

	assert.ProverFailed(&minCircuit{}, &minCircuit{A: -5, B: 11, Min: -5})

	assert.ProverFailed(&minCircuit{}, &minCircuit{A: -10, B: -26, Min: -26})
}

// todo: this circuit does not work, and every test tails!
type assertIsLessCircuit struct {
	A, B frontend.Variable `gnark:",public"`
}

func (c *assertIsLessCircuit) Define(api frontend.API) error {
	bits.ConfigureComparators(api, 3)

	bits.AssertIsLess(c.A, c.B)

	return nil
}

type isLessCircuit struct {
	A, B   frontend.Variable
	IsLess frontend.Variable
}

func (c *isLessCircuit) Define(api frontend.API) error {
	bits.ConfigureComparators(api, 3)

	api.AssertIsEqual(c.IsLess, bits.IsLess(c.A, c.B))

	return nil
}

type minCircuit struct {
	A, B frontend.Variable
	Min  frontend.Variable
}

func (c *minCircuit) Define(api frontend.API) error {
	bits.ConfigureComparators(api, 4)

	api.AssertIsEqual(c.Min, bits.Min(c.A, c.B))

	return nil
}
