package lookup

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type LookupCircuit struct {
	Entries []frontend.Variable
	Queries []frontend.Variable
	Results []frontend.Variable
}

func (c *LookupCircuit) Define(api frontend.API) error {
	table := New()
	for i := range c.Entries {
		table.Insert(c.Entries[i])
	}
	results := table.Lookup(api, c.Queries...)
	if len(results) != len(c.Results) {
		return fmt.Errorf("result length %d expected %d", len(results), len(c.Results))
	}
	for i := range results {
		api.AssertIsEqual(results[i], c.Results[i])
	}
	table.Commit(api)
	return nil
}

func TestLookup(t *testing.T) {
	curve := ecc.BLS12_381
	var err error
	assert := test.NewAssert(t)
	upper := curve.ScalarField()
	nbEntries := 50
	nbQueries := 50
	entries := make([]frontend.Variable, nbEntries)
	for i := range entries {
		entries[i], err = rand.Int(rand.Reader, upper)
		if err != nil {
			t.Fatal(err)
		}
	}
	lookups := make([]frontend.Variable, nbQueries)
	results := make([]frontend.Variable, len(lookups))
	bound := big.NewInt(int64(len(entries)))
	for i := range lookups {
		lookup, err := rand.Int(rand.Reader, bound)
		if err != nil {
			t.Fatal(err)
		}
		lookups[i] = lookup
		results[i] = entries[lookup.Int64()]
	}
	circuit := LookupCircuit{Entries: make([]frontend.Variable, len(entries)), Queries: make([]frontend.Variable, len(lookups)), Results: make([]frontend.Variable, len(results))}
	witness := LookupCircuit{Entries: entries, Queries: lookups, Results: results}
	assert.ProverSucceeded(&circuit, &witness)
}

func ExampleTable() {
	// In real circuits the api variable is provided by the frontend compiler
	api := frontend.API(nil)
	// In real circuits the variables are provided as witness
	c := struct {
		Entries []frontend.Variable
		Queries []frontend.Variable
		Results []frontend.Variable
	}{
		Entries: make([]frontend.Variable, 6),
		Queries: make([]frontend.Variable, 2),
		Results: make([]frontend.Variable, 2),
	}
	// we first initialize a new lookup table
	table := New()
	// we insert the variables we want to look up from
	for i := range c.Entries {
		table.Insert(c.Entries[i])
	}
	// c.Queries is slice of indices we want to obtain from the lookup table.
	results := table.Lookup(api, c.Queries...)
	if len(results) != len(c.Results) {
		fmt.Printf("result length %d expected %d", len(results), len(c.Results))
		return
	}
	for i := range results {
		api.AssertIsEqual(results[i], c.Results[i])
	}
	// the lookups are performed 'lazily'. To actually constrain the values
	// returned by calls to Lookup(), we have to commit the lookup table.
	table.Commit(api)
}
