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

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/logderivarg"
)

// func init() {
// 	solver.RegisterHint(GetHints()...)
// }

// // GetHints returns all hints used in the package.
// func GetHints() []solver.Hint {
// 	return []solver.Hint{lookupHint}
// }

// Table holds all the entries and queries.
type Table struct {
	api frontend.API

	entries   []frontend.Variable
	immutable bool
	results   []result

	bID       constraint.BlueprintID
	blueprint BlueprintLookupHint
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
	t.bID = api.Compiler().AddBlueprint(&t.blueprint)
	return t
}

// Insert inserts variable val into the lookup table and returns its index as a
// constant. It panics if the table is already committed.
func (t *Table) Insert(val frontend.Variable) (index int) {
	if t.immutable {
		panic("inserting into committed lookup table")
	}
	t.entries = append(t.entries, val)

	// 1. update the blueprint with the entry
	v := t.api.Compiler().ToCanonicalVariable(val)
	v.CompressLE(&t.blueprint.EntriesCalldata)

	return len(t.entries) - 1
}

// Lookup lookups up values from the lookup tables given by the indices inds. It
// returns a variable for every index. It panics during compile time when
// looking up from a committed or empty table. It panics during solving time
// when the index is out of bounds.
func (t *Table) Lookup(inds ...frontend.Variable) (vals []frontend.Variable) {
	if t.immutable {
		panic("looking up from a committed lookup table")
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
	// we encode the "call to the lookup hint"
	// as a blueprint.
	//
	// the entry table is stored only once in the blueprint object itself.
	// the calldata slice is:
	// 0. len(calldata) --> blueprint convention.
	// 1. len(entries) --> can change overtime so we keep an offset here
	// 2. len(inputs)
	// 3. calldata(inputs)
	// 4. output range --> the wire ids of the resulting variables
	compiler := t.api.Compiler()

	calldata := make([]uint32, 3, 3+len(inds)*2+2)
	calldata[1] = uint32(len(t.entries))
	calldata[2] = uint32(len(inds))

	// encode inputs
	for _, in := range inds {
		v := compiler.ToCanonicalVariable(in)
		v.CompressLE(&calldata)
	}

	// by convention, first calldata is len of inputs
	calldata[0] = uint32(len(calldata))

	// now what we are left to do is add an instruction to the constraint system
	// such that at solving time the blueprint can properly execute the lookup logic.
	outputs := compiler.AddInstruction(t.bID, calldata)

	if len(outputs) != len(inds) {
		panic("sanity check")
	}

	res := make([]frontend.Variable, len(inds))
	results := make([]result, len(inds))
	for i := range inds {
		res[i] = compiler.InternalVariable(outputs[i])
		results[i] = result{ind: inds[i], val: res[i]}
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

// func lookupHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
// 	nbTable := len(in) - len(out)
// 	for i := 0; i < len(in)-nbTable; i++ {
// 		if !in[nbTable+i].IsInt64() {
// 			return fmt.Errorf("lookup query not integer")
// 		}
// 		ptr := int(in[nbTable+i].Int64())
// 		if ptr >= nbTable {
// 			return fmt.Errorf("lookup query %d outside table size %d", ptr, nbTable)
// 		}
// 		out[i].Set(in[ptr])
// 	}
// 	return nil
// }

type BlueprintLookupHint struct {
	// store the table
	EntriesCalldata []uint32
}

func (b *BlueprintLookupHint) Solve(s constraint.Solver, inst constraint.Instruction) error {
	nbEntries := int(inst.Calldata[1])
	entries := make([]constraint.Element, nbEntries)

	// read the entries
	// TODO cache that.
	offset, delta := 0, 0
	for i := 0; i < nbEntries; i++ {
		entries[i], delta = s.Read(b.EntriesCalldata[offset:])
		offset += delta
	}

	nbInputs := int(inst.Calldata[2])

	// read the inputs
	inputs := make([]constraint.Element, nbInputs)
	offset, delta = 3, 0
	for i := 0; i < nbInputs; i++ {
		inputs[i], delta = s.Read(inst.Calldata[offset:])
		offset += delta
	}

	// read the outputs
	nbOutputs := nbInputs

	for i := 0; i < nbOutputs; i++ {
		ptr := inputs[i]
		idx, isUint64 := s.Uint64(ptr)
		if !isUint64 {
			return fmt.Errorf("lookup query not integer")
		}
		if idx >= uint64(len(entries)) {
			return fmt.Errorf("idx too large")
		}
		s.SetValue(uint32(i+int(inst.WireOffset)), entries[idx])
	}
	return nil
}

func (b *BlueprintLookupHint) CalldataSize() int {
	return -1
}
func (b *BlueprintLookupHint) NbConstraints() int {
	return 0
}

// NbOutputs return the number of output wires this blueprint creates.
func (b *BlueprintLookupHint) NbOutputs(inst constraint.Instruction) int {
	return int(inst.Calldata[2])
}

// Wires returns a function that walks the wires appearing in the blueprint.
// This is used by the level builder to build a dependency graph between instructions.
func (b *BlueprintLookupHint) Wires(inst constraint.Instruction) func(cb func(wire uint32)) {
	return func(cb func(wire uint32)) {
		// depend on the table UP to the number of entries at time of instruction creation.
		nbEntries := int(inst.Calldata[1])

		j := 0
		for i := 0; i < nbEntries; i++ {
			// first we have the length of the linear expression
			n := int(b.EntriesCalldata[j])
			j++
			for k := 0; k < n; k++ {
				t := constraint.Term{CID: b.EntriesCalldata[j], VID: b.EntriesCalldata[j+1]}
				if !t.IsConstant() {
					cb(t.VID)
				}
				j += 2
			}
		}

		// then we have the inputs
		nbInputs := int(inst.Calldata[2])
		j = 3
		for i := 0; i < nbInputs; i++ {
			// first we have the length of the linear expression
			n := int(inst.Calldata[j])
			j++
			for k := 0; k < n; k++ {
				t := constraint.Term{CID: inst.Calldata[j], VID: inst.Calldata[j+1]}
				if !t.IsConstant() {
					cb(t.VID)
				}
				j += 2
			}
		}

		// finally we have the outputs
		for i := 0; i < nbInputs; i++ {
			cb(uint32(i + int(inst.WireOffset)))
		}
	}
}
