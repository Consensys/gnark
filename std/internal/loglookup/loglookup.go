package loglookup

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/multicommit"
)

// XXX: right now only handle constant in table. It becomes slightly difficult
// when the inputs may be variables as we want in general to check that the
// multiplicity of the elements is 1. But this would require sorting the inputs
// and asserting that all two consequtive are different. But sorting by defualt
// is expensive. Maybe can do with product argument?

// XXX: right now we assume that inputs+outputs fit into the scalar field. But
// it should in general be possible to use a random linear combination

// TODO: table is only constants or can also be variables
// TODO: check duplicates?
// build

type committerAPI interface {
	frontend.API
	frontend.Committer
}

type retVals []uint
type query struct {
	inX, inY frontend.Variable
	rets     []frontend.Variable
}

type Table struct {
	rchecker frontend.Rangechecker
	compute  solver.Hint
	queries  []query
}

func build(api committerAPI, table []frontend.Variable, queries []frontend.Variable) {
	compiler := api.Compiler()
	for i := range table {
		if _, isConst := compiler.ConstantValue(table[i]); !isConst {
			panic("table input is not constant")
		}
	}
	countInputs := []frontend.Variable{len(table)}
	countInputs = append(countInputs, table...)
	countInputs = append(countInputs, queries...)
	exps, err := api.NewHint(countHint, len(table), countInputs...)
	if err != nil {
		panic(err)
	}
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		var lp frontend.Variable = 0
		for i := range table {
			tmp := api.DivUnchecked(exps[i], api.Sub(commitment, table[i]))
			lp = api.Add(lp, tmp)
		}
		var rp frontend.Variable = 0
		for i := range queries {
			tmp := api.Inverse(api.Sub(commitment, queries[i]))
			rp = api.Add(rp, tmp)
		}
		api.AssertIsEqual(lp, rp)
		return nil
	}, append(exps, queries...))
}

func countHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) == 0 {
		return fmt.Errorf("at least one input required")
	}
	if !inputs[0].IsInt64() {
		return fmt.Errorf("first element must be length of table")
	}
	nbTable := int(inputs[0].Int64())
	if len(inputs) < 1+nbTable {
		return fmt.Errorf("input doesn't fit table")
	}
	if len(outputs) != nbTable {
		return fmt.Errorf("output not table size")
	}
	histo := make(map[string]int64, nbTable) // string key as big ints not comparable
	for i := 1; i < 1+nbTable; i++ {
		k := inputs[i].String()
		if _, ok := histo[k]; ok {
			return fmt.Errorf("duplicate key")
		}
		histo[k] = 0
	}
	for i := 1 + nbTable; i < len(inputs); i++ {
		k := inputs[i].String()
		v, ok := histo[k]
		if !ok {
			return fmt.Errorf("query element not in table")
		}
		v++
		histo[k] = v
	}
	for i := 1; i < 1+nbTable; i++ {
		k := inputs[i].String()
		outputs[i-1].Set(big.NewInt(histo[k]))
	}
	return nil
}
