package loglookup

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/multicommit"
	"github.com/consensys/gnark/std/rangecheck"
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

type Table struct {
	api      committerAPI
	rchecker frontend.Rangechecker
	compute  solver.Hint
	queries  []frontend.Variable
	rets     retVals
}

func New(api frontend.API, fn solver.Hint, rets retVals) (*Table, error) {
	// check that the output lengths fit into a single element
	var s uint = 16
	for _, v := range rets {
		s += v
	}
	if s >= uint(api.Compiler().FieldBitLen()) {
		return nil, fmt.Errorf("result doesn't fit into field element")
	}
	capi, ok := api.(committerAPI)
	if !ok {
		return nil, fmt.Errorf("API not committer")
	}
	rchecker := rangecheck.New(capi)
	t := &Table{
		api:      capi,
		rchecker: rchecker,
		compute:  fn,
		queries:  nil,
		rets:     rets,
	}
	capi.Compiler().Defer(func(api frontend.API) error {
		capi, ok := api.(committerAPI)
		if !ok {
			return fmt.Errorf("API not committer")
		}
		return t.build(capi)
	})
	return t, nil
}

func (t *Table) pack(x, y frontend.Variable, rets []frontend.Variable) frontend.Variable {
	shift := big.NewInt(1 << 8)
	packed := t.api.Add(x, t.api.Mul(y, shift))
	for i := range t.rets {
		shift.Lsh(shift, t.rets[i])
		packed = t.api.Add(packed, t.api.Mul(rets[i], shift))
	}
	return packed
}

func (t *Table) Query(x, y frontend.Variable) []frontend.Variable {
	t.rchecker.Check(x, 8)
	t.rchecker.Check(y, 8)
	rets, err := t.api.Compiler().NewHint(t.compute, len(t.rets), x, y)
	if err != nil {
		panic(err)
	}
	for i := range t.rets {
		t.rchecker.Check(rets[i], int(t.rets[i]))

	}
	packed := t.pack(x, y, rets)
	t.queries = append(t.queries, packed)
	return rets
}

func (t *Table) buildTable() []frontend.Variable {
	tmp := new(big.Int)
	shift := new(big.Int)
	tbl := make([]frontend.Variable, 65536)
	inputs := []*big.Int{big.NewInt(0), big.NewInt(0)}
	outputs := make([]*big.Int, len(t.rets))
	for i := range outputs {
		outputs[i] = new(big.Int)
	}
	for x := int64(0); x < 256; x++ {
		inputs[0].SetInt64(x)
		for y := int64(0); y < 256; y++ {
			shift.SetInt64(1 << 8)
			i := x | (y << 8)
			inputs[1].SetInt64(y)
			if err := t.compute(t.api.Compiler().Field(), inputs, outputs); err != nil {
				panic(err)
			}
			tblval := new(big.Int).SetInt64(i)
			for j := range t.rets {
				shift.Lsh(shift, t.rets[j])
				tblval.Add(tblval, tmp.Mul(outputs[j], shift))
			}
			tbl[i] = tblval
		}
	}
	return tbl
}

func (t *Table) build(api committerAPI) error {
	table := t.buildTable()
	countInputs := []frontend.Variable{len(table)}
	countInputs = append(countInputs, table...)
	countInputs = append(countInputs, t.queries...)
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
		for i := range t.queries {
			tmp := api.Inverse(api.Sub(commitment, t.queries[i]))
			rp = api.Add(rp, tmp)
		}
		api.AssertIsEqual(lp, rp)
		return nil
	}, append(exps, t.queries...)...)
	return nil
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
