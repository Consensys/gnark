/*
Package lookup implements append-only lookup tables.

This package provides an append-only lookup table which can be used to elements
by their index from a slice. Both the elements in the lookup table and queries
can be public or private variables. For looking up using a constant index, use
standard Go arrays which provide the best performance. This package does not
provide a fast path for the cases where the elements in the lookup tables are
constants.

In R1CS, the approximate cost for the lookup table is 3*(k+n)*log_2(k+n)
constraints where k is the number of entries in the lookup table and n is the
number of total lookups.
*/
package lookup

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/permutation"
)

func init() {
	hint.Register(LookupHint)
	hint.Register(SortingHint)
}

type entry struct {
	pointer frontend.Variable
	current frontend.Variable
}

// Table is an append-only lookup table. It does not allow removing or modifying
// the inserted variables. Inserts and lookups can be performed in any order
// before the lookup table is committed. If the table isn't committed before
// returning from the [frontend.Circuit.Define] method of the circuit, then the
// returned variables are left unconstrained.
//
// Empty type is a valid lookup table, but recommendation is to use [New] method
// for possible forward-compatibility with additionaly optimisations.
type Table struct {
	// entries is a list of inserted elements into the table. If we would be to
	// implement a full RAM, then would be better if it would be list of entry
	// because we need to store the timestamp also, but for now to keep simple
	// keep as []frontend.Variable
	entries []frontend.Variable
	// m is for protecting parallel accesses
	m sync.Mutex

	// we have to collect all variables to lookup between first and then can
	// start looking up. Indicate if we can insert elements
	immutable bool

	results []entry
}

// New returns a new initialized lookup table.
func New() *Table {
	return &Table{}
}

// Insert inserts variable val into the lookup table and returns its index as a
// constant. It panics if the table is already committed.
func (t *Table) Insert(val frontend.Variable) (index int) {
	t.m.Lock()
	defer t.m.Unlock()
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
func (t *Table) Lookup(api frontend.API, inds ...frontend.Variable) (vals []frontend.Variable) {
	t.m.Lock()
	defer t.m.Unlock()
	if t.immutable {
		panic("looking up from a commited lookup table")
	}
	if len(inds) == 0 {
		return nil
	}
	if len(t.entries) == 0 {
		panic("looking up from empty table")
	}
	return t.callLookupHint(api, inds)
}

func (t *Table) callLookupHint(api frontend.API, inds []frontend.Variable) []frontend.Variable {
	inputs := make([]frontend.Variable, len(t.entries)+len(inds))
	copy(inputs[:len(t.entries)], t.entries)
	for i := range inds {
		inputs[len(t.entries)+i] = inds[i]
	}
	hintResp, err := api.NewHint(LookupHint, len(inds), inputs...)
	if err != nil {
		panic(fmt.Sprintf("lookup hint: %v", err))
	}
	res := make([]frontend.Variable, len(inds))
	results := make([]entry, len(inds))
	for i := range inds {
		res[i] = hintResp[i]
		results[i] = entry{pointer: inds[i], current: hintResp[i]}
	}
	t.results = append(t.results, results...)
	return res
}

// LookupHint is a hint function used by the solver to retrieve the value from
// the lookup table. It must be provided to the solver at solving time when
// using lookup tables.
func LookupHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
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

// Commit commits the lookup table, making it immutable and constructing the
// permutation which proves the correctness of the looked up values.
func (t *Table) Commit(api frontend.API) {
	t.m.Lock()
	defer t.m.Unlock()
	t.immutable = true
	// 1. construct the input to the permutation network. It is pairs [index,
	// value, prev_value] for all the inserted elements and queried elements.
	//
	// 2. permute using the permutation network
	//
	// 3. after the permutation, constrain the sorted elements -- start from the
	// second and if the indices are the same, check that current_i =
	// current_(i-1)

	// input to permutation network
	if len(t.entries) == 0 || len(t.results) == 0 {
		// if either the table is empty or there have been no lookups, then omit
		// proving correctness.
		return
	}
	inputs := make([]entry, len(t.entries)+len(t.results))
	for i := 0; i < len(t.entries); i++ {
		inputs[i] = entry{pointer: i, current: t.entries[i]}
	}
	for i := range t.results {
		inputs[len(t.entries)+i] = t.results[i]
	}
	sorted := t.callSortingHint(api, inputs)
	for i := 1; i < len(sorted); i++ {
		ptrDiff := api.Sub(sorted[i].pointer, sorted[i-1].pointer)
		api.AssertIsBoolean(ptrDiff)
		l := api.Mul(api.Sub(1, ptrDiff), api.Sub(sorted[i].current, sorted[i-1].current))
		api.AssertIsEqual(l, 0)
	}
}

func (t *Table) callSortingHint(api frontend.API, inputs []entry) (sorted []entry) {
	ptrs := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		ptrs[i] = inputs[i].pointer
	}
	switches, err := api.NewHint(SortingHint, permutation.NbSwitches(len(inputs)), ptrs...)
	if err != nil {
		panic(fmt.Sprintf("new hint: %v", err))
	}
	routeCb := t.routingLoadCallback(api, switches)
	identityPermutation := permutation.Index(len(inputs))
	permOut, _, err := permutation.Route(identityPermutation, routeCb, inputs)
	if err != nil {
		panic(fmt.Sprintf("build routing: %v", err))
	}
	return permOut
}

// SortingHint is a hint function which computes the switch values in the
// routing network used for proving correctness of the permutation. It must be
// provided to the solver during solving-time when using lookup tables.
func SortingHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	p := permutation.Sorted(inputs)
	routeCb := routingStoreCallback(outputs)
	_, _, err := permutation.Route(p, routeCb, inputs)
	if err != nil {
		panic(fmt.Sprintf("route: %v", err))
	}
	return nil
}

func (t *Table) routingLoadCallback(api frontend.API, switches []frontend.Variable) permutation.RoutingCallback[entry] {
	return func(_ permutation.SwitchState, inUp, inDown entry, layer, layerIndex int, pre bool, globalIndex int) (outUp entry, outDown entry) {
		if globalIndex >= len(switches) {
			panic("switch index larger than stored values")
		}
		// this callback is called for the identity permutation. The switch
		// state we get from the routing network is not valid. We use the
		// routing network builder only for calling the callback in correct
		// order
		s := switches[globalIndex]
		api.AssertIsBoolean(s)
		outUp.pointer = api.Select(s, inDown.pointer, inUp.pointer)
		outUp.current = api.Select(s, inDown.current, inUp.current)
		outDown.pointer = api.Sub(api.Add(inUp.pointer, inDown.pointer), outUp.pointer)
		outDown.current = api.Sub(api.Add(inUp.current, inDown.current), outUp.current)
		return outUp, outDown
	}
}

func routingStoreCallback(output []*big.Int) permutation.RoutingCallback[*big.Int] {
	return func(s permutation.SwitchState, inUp, inDown *big.Int, layer, layerIndex int, pre bool, globalIndex int) (outUp *big.Int, outDown *big.Int) {
		if globalIndex >= len(output) {
			panic("index larger than allocated outputs")
		}
		if s == permutation.STRAIGHT {
			output[globalIndex].SetUint64(0)
			outUp, outDown = inUp, inDown
		} else {
			output[globalIndex].SetUint64(1)
			outUp, outDown = inDown, inUp
		}
		return
	}
}
