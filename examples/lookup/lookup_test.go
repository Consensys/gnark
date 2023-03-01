package lookup

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestLookup(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(
		&LookupExampleCircuit{
			Entries: make([]frontend.Variable, 6),
			Queries: make([]frontend.Variable, 2),
			Results: make([]frontend.Variable, 2),
		},
		&LookupExampleCircuit{
			Entries: []frontend.Variable{10, 20, 30, 40, 50, 60},
			Queries: []frontend.Variable{2, 4},
			Results: []frontend.Variable{30, 50},
		},
	)
}
