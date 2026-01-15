package rangecheck

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/frontendtype"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/internal/logderivarg"
)

type ctxCheckerKey struct{}

func init() {
	solver.RegisterHint(DecomposeHint)
}

type checkedVariable struct {
	v    frontend.Variable
	bits int
}

type commitChecker struct {
	api frontend.API

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
	cht := &commitChecker{api: api}
	kv.SetKeyValue(ctxCheckerKey{}, cht)
	api.Compiler().Defer(cht.commit)
	return cht
}

func (c *commitChecker) Check(in frontend.Variable, bits int) {
	if c.closed {
		panic("checker already closed")
	}
	switch bits {
	case 0:
		c.api.AssertIsEqual(in, 0)
	case 1:
		c.api.AssertIsBoolean(in)
	default:
		c.collected = append(c.collected, checkedVariable{v: in, bits: bits})
	}
}

func (c *commitChecker) buildTable(nbTable int) []frontend.Variable {
	tbl := make([]frontend.Variable, nbTable)
	for i := 0; i < nbTable; i++ {
		tbl[i] = i
	}
	return tbl
}

func (c *commitChecker) commit(api frontend.API) error {
	if c.closed {
		return nil
	}
	defer func() { c.closed = true }()
	if len(c.collected) == 0 {
		return nil
	}
	baseLength := c.getOptimalBasewidth(api)
	// decompose into smaller limbs
	decomposed := make([]frontend.Variable, 0, len(c.collected))
	collected := make([]frontend.Variable, len(c.collected))
	coef := new(big.Int)
	one := big.NewInt(1)

	// check if PlonkAPI is available for optimized constraint generation
	plonkAPI, hasPlonkAPI := api.(frontend.PlonkAPI)

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
		c.assertRecomposition(api, plonkAPI, hasPlonkAPI, limbs, c.collected[i].v, baseLength, coef, one)
		// we have split the input into nbLimbs partitions of length baseLength.
		// This ensures that the checked variable is not more than
		// nbLimbs*baseLength bits, but was requested to be c.collected[i].bits,
		// which may be less. Conditionally add one more check to the most
		// significant partition. If shift is the difference between
		// nbLimbs*baseLength and c.collected[i].bits, then check that MS*2^diff
		// is also baseLength. Because of both checks for MS and MS*2^diff give
		// ensure that the value are small we cannot have overflow.
		shift := nbLimbs*baseLength - c.collected[i].bits
		if shift > 0 {
			msLimbShifted := api.Mul(limbs[nbLimbs-1], coef.Lsh(one, uint(shift)))
			decomposed = append(decomposed, msLimbShifted)
		}
	}
	nbTable := 1 << baseLength
	return logderivarg.Build(api, logderivarg.AsTable(c.buildTable(nbTable)), logderivarg.AsTable(decomposed))
}

// assertRecomposition checks that limbs correctly recompose to the original value.
// For PlonK (SCS) backend, uses optimized PlonkAPI to reduce constraint count.
func (c *commitChecker) assertRecomposition(api frontend.API, plonkAPI frontend.PlonkAPI, hasPlonkAPI bool, limbs []frontend.Variable, original frontend.Variable, baseLength int, coef *big.Int, one *big.Int) {
	nbLimbs := len(limbs)
	if nbLimbs == 0 {
		api.AssertIsEqual(0, original)
		return
	}
	if nbLimbs == 1 {
		api.AssertIsEqual(limbs[0], original)
		return
	}

	// Check if we can use PlonkAPI optimization.
	// The coefficients (powers of 2^baseLength) must fit in int for PlonkAPI.
	// Max coefficient is 2^(baseLength*(nbLimbs-1)).
	// We use 62 bits as safe limit for int64 (leaving room for sign bit and safety).
	maxBits := baseLength * (nbLimbs - 1)
	canUsePlonkAPI := hasPlonkAPI && maxBits <= 62

	if canUsePlonkAPI {
		// Use PlonkAPI for optimized constraint generation.
		// For n limbs, this uses n-1 constraints instead of n with the generic API.
		// EvaluatePlonkExpression returns res = qL*a + qR*b + qM*a*b + qC
		// AddPlonkConstraint asserts qL*a + qR*b + qM*a*b + qO*o + qC = 0

		// Start with first two limbs: composed = limbs[0] + limbs[1] * 2^baseLength
		coefVal := 1 << baseLength
		var composed frontend.Variable
		if nbLimbs == 2 {
			// For 2 limbs, directly assert: limbs[0] + limbs[1]*coef - original = 0
			// qL=1, qR=coef, qM=0, qO=-1, qC=0
			plonkAPI.AddPlonkConstraint(limbs[0], limbs[1], original, 1, coefVal, -1, 0, 0)
			return
		}

		// For 3+ limbs, build up the composed value
		composed = plonkAPI.EvaluatePlonkExpression(limbs[0], limbs[1], 1, coefVal, 0, 0)

		// Add remaining limbs except the last one
		for j := 2; j < nbLimbs-1; j++ {
			coefVal = 1 << (baseLength * j)
			composed = plonkAPI.EvaluatePlonkExpression(composed, limbs[j], 1, coefVal, 0, 0)
		}

		// For the last limb, combine with the assertion
		coefVal = 1 << (baseLength * (nbLimbs - 1))
		// composed + limbs[last]*coef - original = 0
		plonkAPI.AddPlonkConstraint(composed, limbs[nbLimbs-1], original, 1, coefVal, -1, 0, 0)
	} else {
		// Fallback to generic API (for R1CS or when coefficients don't fit in int)
		var composed frontend.Variable = 0
		for j := range limbs {
			composed = api.Add(composed, api.Mul(limbs[j], coef.Lsh(one, uint(baseLength*j))))
		}
		api.AssertIsEqual(composed, original)
	}
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
	min := int64(math.MaxInt64)
	minVal := 0
	for j := 2; j < 18; j++ {
		current := int64(countFn(j, collected))
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
		nbVarLimbs := int(decompSize(collected[i].bits, baseLength))
		if nbVarLimbs*baseLength > collected[i].bits {
			nbVarLimbs += 1
		}
		nbDecomposed += int(nbVarLimbs)
	}
	eqs := len(collected)       // correctness of decomposition
	nbRight := nbDecomposed     // inverse per decomposed
	nbleft := (1 << baseLength) // div per table
	return nbleft + nbRight + eqs + 1
}

func nbPLONKConstraints(baseLength int, collected []checkedVariable) int {
	nbDecomposed := 0
	for i := range collected {
		nbVarLimbs := int(decompSize(collected[i].bits, baseLength))
		if nbVarLimbs*baseLength > collected[i].bits {
			nbVarLimbs += 1
		}
		nbDecomposed += int(nbVarLimbs)
	}
	eqs := nbDecomposed               // check correctness of every decomposition. this is nbDecomp adds + eq cost per collected
	nbRight := 3 * nbDecomposed       // denominator sub, inv and large sum per table entry
	nbleft := 3 * (1 << baseLength)   // denominator sub, div and large sum per table entry
	return nbleft + nbRight + eqs + 1 // and the final assert
}
