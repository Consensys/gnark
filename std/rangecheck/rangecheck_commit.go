package rangecheck

import (
	"fmt"
	"math"
	"math/big"
	stdbits "math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/frontendtype"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/math/bits"
)

type ctxCheckerKey struct{}

func init() {
	solver.RegisterHint(DecomposeHint, CountHint)
}

type checkedVariable struct {
	v    frontend.Variable
	bits int
}

type commitChecker struct {
	collected []checkedVariable
	closed    bool
}

func newCommitRangechecker(api frontend.API) *commitChecker {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("builder should implement key-value store")
	}
	ch := kv.GetKeyValue(ctxCheckerKey{})
	if ch != nil {
		if cht, ok := ch.(*commitChecker); ok {
			return cht
		} else {
			panic("stored rangechecker is not valid")
		}
	}
	cht := &commitChecker{}
	kv.SetKeyValue(ctxCheckerKey{}, cht)
	api.Compiler().Defer(cht.commit)
	return cht
}

func (c *commitChecker) Check(in frontend.Variable, bits int) {
	if c.closed {
		panic("checker already closed")
	}
	c.collected = append(c.collected, checkedVariable{v: in, bits: bits})
}

func (c *commitChecker) commit(api frontend.API) error {
	if c.closed {
		return nil
	}
	defer func() { c.closed = true }()
	if len(c.collected) == 0 {
		return nil
	}
	committer, ok := api.(frontend.Committer)
	if !ok {
		panic("expected committer API")
	}
	baseLength := c.getOptimalBasewidth(api)
	// decompose into smaller limbs
	decomposed := make([]frontend.Variable, 0, len(c.collected))
	collected := make([]frontend.Variable, len(c.collected))
	base := new(big.Int).Lsh(big.NewInt(1), uint(baseLength))
	for i := range c.collected {
		// collect all vars for commitment input
		collected[i] = c.collected[i].v
		// decompose value into limbs
		nbLimbs := decompSize(c.collected[i].bits, baseLength)
		limbs, err := api.Compiler().NewHint(DecomposeHint, int(nbLimbs), c.collected[i].bits, baseLength, c.collected[i].v)
		if err != nil {
			panic(fmt.Sprintf("decompose %v", err))
		}
		// store all limbs for counting
		decomposed = append(decomposed, limbs...)
		// check that limbs are correct. We check the sizes of the limbs later
		var composed frontend.Variable = 0
		for j := range limbs {
			composed = api.Add(composed, api.Mul(limbs[j], new(big.Int).Exp(base, big.NewInt(int64(j)), nil)))
		}
		api.AssertIsEqual(composed, c.collected[i].v)
	}
	nbTable := 1 << baseLength
	// compute the counts for every value in the range
	exps, err := api.Compiler().NewHint(CountHint, nbTable, decomposed...)
	if err != nil {
		panic(fmt.Sprintf("count %v", err))
	}
	// compute the poly \pi (X - s_i)^{e_i}
	commitment, err := committer.Commit(collected...)
	if err != nil {
		panic(fmt.Sprintf("commit %v", err))
	}
	logn := stdbits.Len(uint(len(decomposed)))
	var lp frontend.Variable = 1
	for i := 0; i < nbTable; i++ {
		expbits := bits.ToBinary(api, exps[i], bits.WithNbDigits(logn))
		var acc frontend.Variable = 1
		tmp := api.Sub(commitment, i)
		for j := 0; j < logn; j++ {
			curr := api.Select(expbits[j], tmp, 1)
			acc = api.Mul(acc, curr)
			tmp = api.Mul(tmp, tmp)
		}
		lp = api.Mul(lp, acc)
	}
	// compute the poly \pi (X - f_i)
	var rp frontend.Variable = 1
	for i := range decomposed {
		val := api.Sub(commitment, decomposed[i])
		rp = api.Mul(rp, val)
	}
	api.AssertIsEqual(lp, rp)
	return nil
}

func decompSize(varSize int, limbSize int) int {
	return (varSize + limbSize - 1) / limbSize
}

// DecomposeHint is a hint used for range checking with commitment. It
// decomposes large variables into chunks which can be individually range-check
// in the native range.
func DecomposeHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("input must be 3 elements")
	}
	if !inputs[0].IsUint64() || !inputs[1].IsUint64() {
		return fmt.Errorf("first two inputs have to be uint64")
	}
	varSize := int(inputs[0].Int64())
	limbSize := int(inputs[1].Int64())
	val := inputs[2]
	nbLimbs := decompSize(varSize, limbSize)
	if len(outputs) != nbLimbs {
		return fmt.Errorf("need %d outputs instead to decompose", nbLimbs)
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(limbSize))
	tmp := new(big.Int).Set(val)
	for i := 0; i < len(outputs); i++ {
		outputs[i].Mod(tmp, base)
		tmp.Rsh(tmp, uint(limbSize))
	}
	return nil
}

// CountHint is a hint function which is used in range checking using
// commitment. It counts the occurences of checked variables in the range and
// returns the counts.
func CountHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nbVals := len(outputs)
	if len(outputs) != nbVals {
		return fmt.Errorf("output size %d does not match range size %d", len(outputs), nbVals)
	}
	counts := make(map[uint64]uint64, nbVals)
	for i := 0; i < len(inputs); i++ {
		if !inputs[i].IsUint64() {
			return fmt.Errorf("input %d not uint64", i)
		}
		c := inputs[i].Uint64()
		counts[c]++
	}
	for i := 0; i < nbVals; i++ {
		outputs[i].SetUint64(counts[uint64(i)])
	}
	return nil
}

func (c *commitChecker) getOptimalBasewidth(api frontend.API) int {
	if ft, ok := api.(frontendtype.FrontendTyper); ok {
		switch ft.FrontendType() {
		case frontendtype.R1CS:
			return optimalWidth(nbR1CSConstraints, c.collected)
		case frontendtype.SCS:
			return optimalWidth(nbPLONKConstraints, c.collected)
		}
	}
	return optimalWidth(nbR1CSConstraints, c.collected)
}

func optimalWidth(countFn func(baseLength int, collected []checkedVariable) int, collected []checkedVariable) int {
	min := math.MaxInt64
	minVal := 0
	for j := 2; j < 18; j++ {
		current := countFn(j, collected)
		if current < min {
			min = current
			minVal = j
		}
	}
	return minVal
}

func nbR1CSConstraints(baseLength int, collected []checkedVariable) int {
	nbDecomposed := 0
	for i := range collected {
		nbDecomposed += int(decompSize(collected[i].bits, baseLength))
	}
	eqs := len(collected) // single composition check per collected
	logn := stdbits.Len(uint(nbDecomposed))
	nbTable := 1 << baseLength
	nbLeft := nbTable *
		(logn + // tobinary
			logn + // select per exponent bit
			logn + // mul per exponent bit
			logn + // mul per exponent bit
			1) // final mul
	nbRight := nbDecomposed           // mul all decomposed
	return nbLeft + nbRight + eqs + 1 // single for final equality
}

func nbPLONKConstraints(baseLength int, collected []checkedVariable) int {
	nbDecomposed := 0
	for i := range collected {
		nbDecomposed += int(decompSize(collected[i].bits, baseLength))
	}
	eqs := nbDecomposed // check correctness of every decomposition. this is nbDecomp adds + eq cost per collected
	logn := stdbits.Len(uint(nbDecomposed))
	nbTable := 1 << baseLength
	nbLeft := nbTable *
		(3*logn + // tobinary. decomposition check + binary check
			2*logn + // select per exponent bit
			logn + // mul per exponent bit
			logn + // mul per exponent bit
			1) // final mul
	nbRight := 2 * nbDecomposed       // per decomposed sub and mul
	return nbLeft + nbRight + eqs + 1 // single for final equality
}
