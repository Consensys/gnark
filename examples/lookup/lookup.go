package lookup

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup"
)

type LookupExampleCircuit struct {
	Entries []frontend.Variable
	Queries []frontend.Variable
	Results []frontend.Variable
}

func (c *LookupExampleCircuit) Define(api frontend.API) error {
	table := lookup.New()
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
