// Package logderivarg implements log-derivative argument.
//
// The log-derivative argument was described in [Haböck22] as an improvement
// over [BCG+18]. In [BCG+18], it was shown that to show inclusion of a multiset
// S in T, one can show
//
//	∏_{f∈F} (x-f)^count(f, S) == ∏_{s∈S} x-s,
//
// where function `count` counts the number of occurrences of f in S. The problem
// with this approach is the high cost for exponentiating the left-hand side of
// the equation. However, in [Haböck22] it was shown that when avoiding the
// poles, we can perform the same check for the log-derivative variant of the
// equation:
//
//	∑_{f∈F} count(f,S)/(x-f) == ∑_{s∈S} 1/(x-s).
//
// Additionally, when the entries of both S and T are vectors, then instead we
// can check random linear combinations. So, when F is a matrix and S is a
// multiset of its rows, we first generate random linear coefficients (r_1, ...,
// r_n) and check
//
//	∑_{f∈F} count(f,S)/(x-∑_{i∈[n]}r_i*f_i) == ∑_{s∈S} 1/(x-∑_{i∈[n]}r_i*s_i).
//
// This package is a low-level primitive for building more extensive gadgets. It
// only checks the last equation, but the tables and queries should be built by
// the users.
//
// NB! The package doesn't check that the entries in table F are unique.
//
// [BCG+18]: https://eprint.iacr.org/2018/380
// [Haböck22]: https://eprint.iacr.org/2022/1530
package logderivarg

// TODO: we handle both constant and variable tables. But for variable tables we
// have to ensure that all the table entries differ! Right now isn't a problem
// because everywhere we build we also have indices which ensure uniqueness. I
// guess the best approach is to have safe and unsafe versions where the safe
// version performs additional sorting. But that is really really expensive as
// we have to show that all sorted values ara monotonically increasing.

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/std/internal/fieldextension"
	"github.com/consensys/gnark/std/internal/mimc"
	"github.com/consensys/gnark/std/multicommit"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hints used in this package
func GetHints() []solver.Hint {
	return []solver.Hint{countHint, countIndexedHint}
}

// Table is a vector of vectors.
type Table [][]frontend.Variable

// AsTable returns a vector as a single-column table.
func AsTable(vector []frontend.Variable) Table {
	ret := make([][]frontend.Variable, len(vector))
	for i := range vector {
		ret[i] = []frontend.Variable{vector[i]}
	}
	return ret
}

// Build builds the argument using the table and queries. If both table and
// queries are multiple-column, then also samples coefficients for the random
// linear combinations.
func Build(api frontend.API, table Table, queries Table) error {
	if len(table) == 0 {
		return errors.New("table empty")
	}
	nbRow := len(table[0])
	constTable := true
	countInputs := []frontend.Variable{len(table), nbRow}
	for i := range table {
		if len(table[i]) != nbRow {
			return errors.New("table row length mismatch")
		}
		if constTable {
			for j := range table[i] {
				if _, isConst := api.Compiler().ConstantValue(table[i][j]); !isConst {
					constTable = false
				}
			}
		}
		countInputs = append(countInputs, table[i]...)
	}
	for i := range queries {
		if len(queries[i]) != nbRow {
			return errors.New("query row length mismatch")
		}
		countInputs = append(countInputs, queries[i]...)
	}
	exps, err := api.NewHint(countHint, len(table), countInputs...)
	if err != nil {
		return fmt.Errorf("hint: %w", err)
	}

	var toCommit []frontend.Variable
	if !constTable {
		for i := range table {
			toCommit = append(toCommit, table[i]...)
		}
	}
	for i := range queries {
		toCommit = append(toCommit, queries[i]...)
	}
	toCommit = append(toCommit, exps...)

	if !smallfields.IsSmallField(api.Compiler().Field()) {
		// handle the commitment over large fields directly
		multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
			rowCoeffs, challenge := randLinearCoefficients(api, nbRow, commitment)
			var lp frontend.Variable = 0
			for i := range table {
				tmp := api.DivUnchecked(exps[i], api.Sub(challenge, randLinearCombination(api, rowCoeffs, table[i])))
				lp = api.Add(lp, tmp)
			}
			var rp frontend.Variable = 0

			toInvert := make([]frontend.Variable, len(queries))
			for i := range queries {
				toInvert[i] = api.Sub(challenge, randLinearCombination(api, rowCoeffs, queries[i]))
			}

			if bapi, ok := api.(frontend.BatchInverter); ok {
				toInvert = bapi.BatchInvert(toInvert)
			} else {
				for i := range toInvert {
					toInvert[i] = api.Inverse(toInvert[i])
				}
			}

			for i := range queries {
				// tmp := api.Inverse(api.Sub(challenge, randLinearCombination(api, rowCoeffs, queries[i])))
				rp = api.Add(rp, toInvert[i])
			}
			api.AssertIsEqual(lp, rp)
			return nil
		}, toCommit...)
	} else {
		// when the native field is small field, then we need to use WithWideCommitment
		extapi, err := fieldextension.NewExtension(api)
		if err != nil {
			return fmt.Errorf("create field extension: %w", err)
		}
		multicommit.WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
			rowCoeffs, challenge := randLinearCofficientsExt(extapi, nbRow, fieldextension.Element(commitment))
			var lp fieldextension.Element
			tableEntriesExts := make([]fieldextension.Element, nbRow)
			for i := range table {
				for j := range tableEntriesExts {
					tableEntriesExts[j] = extapi.AsExtensionVariable(table[i][j])
				}
				tableComb := randLinearCombinationExt(extapi, rowCoeffs, tableEntriesExts)
				denom := extapi.Sub(challenge, tableComb)
				denom = extapi.Inverse(denom)
				expEntryExt := extapi.AsExtensionVariable(exps[i])
				term := extapi.Mul(expEntryExt, denom)
				lp = extapi.Add(lp, term)
			}

			var rp fieldextension.Element
			queryEntryExts := make([]fieldextension.Element, nbRow)
			for i := range queries {
				for j := range queryEntryExts {
					queryEntryExts[j] = extapi.AsExtensionVariable(queries[i][j])
				}
				queryEntryExt := randLinearCombinationExt(extapi, rowCoeffs, queryEntryExts)
				denom := extapi.Sub(challenge, queryEntryExt)
				denom = extapi.Inverse(denom)
				rp = extapi.Add(rp, denom)
			}
			extapi.AssertIsEqual(lp, rp)
			return nil
		}, extapi.Degree(), toCommit...)
	}

	return nil
}

func randLinearCoefficients(api frontend.API, nbRow int, commitment frontend.Variable) (rowCoeffs []frontend.Variable, challenge frontend.Variable) {
	if nbRow == 1 {
		// to avoid initializing the hasher.
		return []frontend.Variable{1}, commitment
	}
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	rowCoeffs = make([]frontend.Variable, nbRow)
	rowCoeffs[0] = 1
	for i := 1; i < nbRow; i++ {
		hasher.Reset()
		hasher.Write(i+1, commitment)
		rowCoeffs[i] = hasher.Sum()
	}
	return rowCoeffs, commitment
}

func randLinearCofficientsExt(extapi fieldextension.Field, nbRow int, commitment fieldextension.Element) (rowCoeffs []fieldextension.Element, challenge fieldextension.Element) {
	if nbRow == 1 {
		// to avoid initializing the hasher.
		return []fieldextension.Element{extapi.One()}, commitment
	}
	// we don't have a hash function over extensions yet. So we use 1, ch, ch^2, ...
	rowCoeffs = make([]fieldextension.Element, nbRow)
	rowCoeffs[0] = extapi.One()
	for i := 1; i < nbRow; i++ {
		rowCoeffs[i] = extapi.Mul(rowCoeffs[i-1], commitment)
	}
	return rowCoeffs, commitment
}

func randLinearCombination(api frontend.API, rowCoeffs []frontend.Variable, row []frontend.Variable) frontend.Variable {
	if len(rowCoeffs) != len(row) {
		panic("coefficient count mismatch")
	}
	var res frontend.Variable = 0
	for i := range rowCoeffs {
		res = api.Add(res, api.Mul(rowCoeffs[i], row[i]))
	}
	return res
}

func randLinearCombinationExt(extapi fieldextension.Field, rowCoeffs []fieldextension.Element, row []fieldextension.Element) fieldextension.Element {
	if len(rowCoeffs) != len(row) {
		panic("coefficient count mismatch")
	}
	res := extapi.Zero()
	for i := range rowCoeffs {
		term := extapi.Mul(rowCoeffs[i], row[i])
		res = extapi.Add(res, term)
	}
	return res
}

func countHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) <= 2 {
		return fmt.Errorf("at least two input required")
	}
	if !inputs[0].IsInt64() {
		return fmt.Errorf("first element must be length of table")
	}
	nbTable := int(inputs[0].Int64())
	if !inputs[1].IsInt64() {
		return fmt.Errorf("first element must be length of row")
	}
	nbRow := int(inputs[1].Int64())
	if len(inputs) < 2+nbTable {
		return fmt.Errorf("input doesn't fit table")
	}
	if len(outputs) != nbTable {
		return fmt.Errorf("output not table size")
	}
	if (len(inputs)-2-nbTable*nbRow)%nbRow != 0 {
		return fmt.Errorf("query count not full integer")
	}
	nbQueries := (len(inputs) - 2 - nbTable*nbRow) / nbRow
	if nbQueries <= 0 {
		return fmt.Errorf("at least one query required")
	}
	nbBytes := (m.BitLen() + 7) / 8
	buf := make([]byte, nbBytes*nbRow)
	histo := make(map[string]int64, nbTable) // string key as big ints not comparable
	for i := 0; i < nbTable; i++ {
		for j := 0; j < nbRow; j++ {
			inputs[2+nbRow*i+j].FillBytes(buf[j*nbBytes : (j+1)*nbBytes])
		}
		k := string(buf)
		if _, ok := histo[k]; ok {
			return fmt.Errorf("duplicate key")
		}
		histo[k] = 0
	}
	for i := 0; i < nbQueries; i++ {
		for j := 0; j < nbRow; j++ {
			inputs[2+nbRow*nbTable+nbRow*i+j].FillBytes(buf[j*nbBytes : (j+1)*nbBytes])
		}
		k := string(buf)
		v, ok := histo[k]
		if !ok {
			return fmt.Errorf("query element not in table")
		}
		v++
		histo[k] = v
	}
	for i := 0; i < nbTable; i++ {
		for j := 0; j < nbRow; j++ {
			inputs[2+nbRow*i+j].FillBytes(buf[j*nbBytes : (j+1)*nbBytes])
		}
		outputs[i].Set(big.NewInt(histo[string(buf)]))
	}
	return nil
}

// countIndexedHint counts occurrences of each index in the indices array.
// inputs[0] = table size, inputs[1:] = indices
// outputs = multiplicities for each table entry
func countIndexedHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 1 {
		return fmt.Errorf("at least table size required")
	}
	if !inputs[0].IsInt64() {
		return fmt.Errorf("table size must be int64")
	}
	tableSize := int(inputs[0].Int64())
	if len(outputs) != tableSize {
		return fmt.Errorf("output size mismatch: got %d, expected %d", len(outputs), tableSize)
	}

	// Initialize to zero
	for i := 0; i < tableSize; i++ {
		outputs[i].SetInt64(0)
	}

	// Count index occurrences
	for i := 1; i < len(inputs); i++ {
		if !inputs[i].IsInt64() {
			return fmt.Errorf("index must be int64")
		}
		idx := int(inputs[i].Int64())
		if idx < 0 || idx >= tableSize {
			return fmt.Errorf("index %d out of bounds [0, %d)", idx, tableSize)
		}
		outputs[idx].Add(outputs[idx], big.NewInt(1))
	}
	return nil
}

// BuildIndexedConstant builds a LogUp* argument for constant identity tables [0,1,...,n-1]
// where table[i] = i, meaning table[index] = index. This is optimized for range checks.
//
// The key optimization over Build is that we don't commit to the query values (indices),
// since for identity tables the query values equal the indices which are already committed
// as part of the circuit structure.
//
// Reference: https://eprint.iacr.org/2025/946
func BuildIndexedConstant(api frontend.API, tableSize int, indices []frontend.Variable) error {
	// For identity tables, query values equal indices, so we can reuse BuildIndexedPrecomputed
	// with table[i] = i
	table := make([]*big.Int, tableSize)
	for i := range table {
		table[i] = big.NewInt(int64(i))
	}
	return BuildIndexedPrecomputed(api, table, indices, indices)
}

// BuildIndexedPrecomputed builds a LogUp* argument for precomputed constant tables.
// This is optimized for cases where table[i] = f(i) for some precomputed function f.
//
// Parameters:
//   - table: constant table values (table[i] is the precomputed value at index i)
//   - indices: variable indices into the table
//   - queryValues: the actual query values (must equal table[indices[i]], NOT committed)
//
// The key optimization over Build is that we don't commit to query values.
// The queryValues are used in the log-derivative equation but not committed,
// saving O(m) commitment elements for m queries.
//
// Reference: https://eprint.iacr.org/2025/946
func BuildIndexedPrecomputed(api frontend.API, table []*big.Int, indices []frontend.Variable, queryValues []frontend.Variable) error {
	if len(table) == 0 {
		return errors.New("table empty")
	}
	if len(indices) == 0 {
		return errors.New("at least one index required")
	}
	if len(indices) != len(queryValues) {
		return errors.New("indices and queryValues length mismatch")
	}

	tableSize := len(table)
	hintInputs := make([]frontend.Variable, 1+len(indices))
	hintInputs[0] = tableSize
	copy(hintInputs[1:], indices)

	mults, err := api.NewHint(countIndexedHint, tableSize, hintInputs...)
	if err != nil {
		return fmt.Errorf("hint: %w", err)
	}

	// Only commit multiplicities (queryValues NOT committed - key LogUp* optimization)
	toCommit := mults

	if !smallfields.IsSmallField(api.Compiler().Field()) {
		multicommit.WithCommitment(api, func(api frontend.API, challenge frontend.Variable) error {
			// LHS: sum_{j=0}^{n-1} mults[j]/(challenge - table[j])
			lhsTerms := make([]frontend.Variable, tableSize)
			for j := 0; j < tableSize; j++ {
				denom := api.Sub(challenge, table[j])
				lhsTerms[j] = api.DivUnchecked(mults[j], denom)
			}
			var lhs frontend.Variable = 0
			for j := 0; j < tableSize; j++ {
				lhs = api.Add(lhs, lhsTerms[j])
			}

			// RHS: sum_{i} 1/(challenge - queryValues[i])
			// queryValues[i] should equal table[indices[i]], verified by the log-derivative check
			toInvert := make([]frontend.Variable, len(queryValues))
			for i := range queryValues {
				toInvert[i] = api.Sub(challenge, queryValues[i])
			}

			if bapi, ok := api.(frontend.BatchInverter); ok {
				toInvert = bapi.BatchInvert(toInvert)
			} else {
				for i := range toInvert {
					toInvert[i] = api.Inverse(toInvert[i])
				}
			}

			var rhs frontend.Variable = 0
			for i := range queryValues {
				rhs = api.Add(rhs, toInvert[i])
			}

			api.AssertIsEqual(lhs, rhs)
			return nil
		}, toCommit...)
	} else {
		extapi, err := fieldextension.NewExtension(api)
		if err != nil {
			return fmt.Errorf("create field extension: %w", err)
		}
		multicommit.WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
			challenge := fieldextension.Element(commitment)

			// LHS over extension field
			var lhs fieldextension.Element
			for j := 0; j < tableSize; j++ {
				tableExt := extapi.AsExtensionVariable(table[j])
				denom := extapi.Sub(challenge, tableExt)
				denom = extapi.Inverse(denom)
				multExt := extapi.AsExtensionVariable(mults[j])
				term := extapi.Mul(multExt, denom)
				lhs = extapi.Add(lhs, term)
			}

			// RHS over extension field
			var rhs fieldextension.Element
			for i := range queryValues {
				qvExt := extapi.AsExtensionVariable(queryValues[i])
				denom := extapi.Sub(challenge, qvExt)
				denom = extapi.Inverse(denom)
				rhs = extapi.Add(rhs, denom)
			}

			extapi.AssertIsEqual(lhs, rhs)
			return nil
		}, extapi.Degree(), toCommit...)
	}

	return nil
}
