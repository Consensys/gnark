// Package logderiv implements append-only lookups using log-derivative
// argument.
//
// The lookup is based on log-derivative argument as described in [logderivarg].
// The lookup table is a matrix where first column is the index and the second
// column the stored values:
//
//	1 x_1
//	2 x_2
//	...
//	n x_n
//
// When performing a query for index i, the prover returns x_i from memory and
// stores (i, x_i) as a query. During the log-derivative argument building we
// check that all queried tuples (i, x_i) are included in the table.
//
// The complexity of the lookups is linear in the size of the table and the
// number of queries (O(n+m)).
package logderivlookup

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/logderivarg"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hints used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{lookupHint}
}

// Table holds all the entries and queries.
type Table struct {
	api frontend.API

	entries   []frontend.Variable
	immutable bool
	results   []result
}

type result struct {
	ind frontend.Variable
	val frontend.Variable
}

// New returns a new [*Table]. It additionally defers building the
// log-derivative argument.
func New(api frontend.API) *Table {
	t := &Table{api: api}
	api.Compiler().Defer(t.commit)
	return t
}

// Insert inserts variable val into the lookup table and returns its index as a
// constant. It panics if the table is already committed.
func (t *Table) Insert(val frontend.Variable) (index int) {
	if t.immutable {
		panic("inserting into commited lookup table")
	}
	t.entries = append(t.entries, val)
	return len(t.entries) - 1
}

// Lookup lookups up values from the lookup tables given by the indices inds. It
// returns a variable for every index. It panics during compile time when
// looking up from a committed or empty table. It panics during solving time
// when the index is out of bounds.
func (t *Table) Lookup(inds ...frontend.Variable) (vals []frontend.Variable) {
	if t.immutable {
		panic("looking up from a commited lookup table")
	}
	if len(inds) == 0 {
		return nil
	}
	if len(t.entries) == 0 {
		panic("looking up from empty table")
	}
	return t.callLookupHint(inds)
}

func (t *Table) callLookupHint(inds []frontend.Variable) []frontend.Variable {
	inputs := make([]frontend.Variable, len(t.entries)+len(inds))
	copy(inputs[:len(t.entries)], t.entries)
	for i := range inds {
		inputs[len(t.entries)+i] = inds[i]
	}
	hintResp, err := t.api.NewHint(lookupHint, len(inds), inputs...)
	if err != nil {
		panic(fmt.Sprintf("lookup hint: %v", err))
	}
	res := make([]frontend.Variable, len(inds))
	results := make([]result, len(inds))
	for i := range inds {
		res[i] = hintResp[i]
		results[i] = result{ind: inds[i], val: hintResp[i]}
	}
	t.results = append(t.results, results...)
	return res
}

func (t *Table) entryTable() [][]frontend.Variable {
	tbl := make([][]frontend.Variable, len(t.entries))
	for i := range t.entries {
		tbl[i] = []frontend.Variable{i, t.entries[i]}
	}
	return tbl
}

func (t *Table) resultsTable() [][]frontend.Variable {
	tbl := make([][]frontend.Variable, len(t.results))
	for i := range t.results {
		tbl[i] = []frontend.Variable{t.results[i].ind, t.results[i].val}
	}
	return tbl
}

func (t *Table) commit(api frontend.API) error {
	return logderivarg.Build(api, t.entryTable(), t.resultsTable())
}

func lookupHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
	nbTable := len(in) - len(out)
	for i := 0; i < len(in)-nbTable; i++ {
		if !in[nbTable+i].IsInt64() {
			return fmt.Errorf("lookup query not integer")
		}
		ptr := int(in[nbTable+i].Int64())
		if ptr >= nbTable {
			return fmt.Errorf("lookup query %d outside table size %d", ptr, nbTable)
		}
		out[i] = in[ptr]
	}
	return nil
}
