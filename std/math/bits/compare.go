package bits

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

func init() {
	// register hints
	solver.RegisterHint(MinOutputHint)
	solver.RegisterHint(IsLessOutputHint)
}

var cmpCfg struct {
	upperAbsDiffBitLen int
	api                frontend.API
}

// ConfigureComparators sets or updates the configuration settings that are used by comparator
// functions in this package.
//
// If upperAbsDiff is the upper bound of the absolute difference of a and b, such that |a - b| <=
// upperAbsDiff, then upperAbsDiffBitLen is the number of bits of the binary representation of
// upperAbsDiff. Lower values of upperAbsDiffBitLen will reduce the number of generated constraints
// significantly. Use upperAbsDiffBitLen = 0 to select the maximum possible value.
//
// As long as BitLen(|a - b|) <= upperAbsDiffBitLen all functions work correctly. If BitLen(|a - b|)
// > upperAbsDiffBitLen >= BitLen(|a - b| - 1) sometimes a proof can not be generated. If BitLen(|a
// - b| - 1) > upperAbsDiffBitLen, as long as |a - b| <= (P - 1) / 2, where P is the order of the
// underlying field, no proofs can be generated. However, when |a - b| > (P - 1) / 2, the behaviour
// of [AssertIsLess], [IsLess] and [Min] will be undefined.
func ConfigureComparators(api frontend.API, upperAbsDiffBitLen int) {
	// We need to have |a - b| <= (P - 1) / 2. The BitLen of (P - 1) / 2 is
	// exactly FieldBitLen()-1, so to ensure the inequality, we should have:
	// upperAbsDiffBitLen <= FieldBitLen()-2
	// todo: by having the order of the field (P) we can implement this with tighter bounds
	if upperAbsDiffBitLen == 0 {
		upperAbsDiffBitLen = api.Compiler().FieldBitLen() - 2
	}
	if upperAbsDiffBitLen > api.Compiler().FieldBitLen()-2 {
		panic("ConfigureComparators: the specified upper bound of absolute difference is too high")
	}
	cmpCfg.upperAbsDiffBitLen = upperAbsDiffBitLen
	cmpCfg.api = api
}

// AssertIsLess defines a set of constraints that can not be satisfied when a < b. So, If a < b no
// proofs can be generated.
//
// Note: Before using this function, the package should be configured by calling
// [ConfigureComparators].
func AssertIsLess(a frontend.Variable, b frontend.Variable) {
	// a < b <==> b - a - 1 >= 0
	toBinary(
		cmpCfg.api,
		cmpCfg.api.Sub(b, a, 1),
		WithNbDigits(cmpCfg.upperAbsDiffBitLen),
	)
}

// IsLess returns 1 if a < b, and returns 0 if a >= b.
//
// Note: Before using this function, the package should be configured by calling
// [ConfigureComparators].
func IsLess(a frontend.Variable, b frontend.Variable) frontend.Variable {
	res, _ := cmpCfg.api.Compiler().NewHint(IsLessOutputHint, 1, a, b, -1)
	indicator := res[0]
	// a < b  <==> b - a - 1 >= 0
	// a >= b <==> a - b >= 0
	toBinary(
		cmpCfg.api,
		cmpCfg.api.Select(indicator, cmpCfg.api.Sub(b, a, 1), cmpCfg.api.Sub(a, b)),
		WithNbDigits(cmpCfg.upperAbsDiffBitLen),
	)
	return indicator
}

// Min returns the minimum of a and b.
//
// Note: Before using this function, the package should be configured by calling
// [ConfigureComparators].
func Min(a frontend.Variable, b frontend.Variable) frontend.Variable {
	res, _ := cmpCfg.api.Compiler().NewHint(MinOutputHint, 1, a, b, -1)
	min := res[0]

	aDiff := cmpCfg.api.Sub(a, min)
	bDiff := cmpCfg.api.Sub(b, min)
	// (a - min) * (b - min) == 0
	cmpCfg.api.AssertIsEqual(0, cmpCfg.api.Mul(aDiff, bDiff))

	// (a - min) + (b - min) >= 0
	toBinary(cmpCfg.api, cmpCfg.api.Add(aDiff, bDiff), WithNbDigits(cmpCfg.upperAbsDiffBitLen))

	return min
}

// cmpInField compares a and b in a finite field of prime order, in which -1 is represented by
// minusOne.
func cmpInField(a *big.Int, b *big.Int, minusOne *big.Int) int {
	biggestPositiveNum := new(big.Int).Rsh(minusOne, 1)
	if a.Cmp(biggestPositiveNum)*b.Cmp(biggestPositiveNum) == -1 {
		return -a.Cmp(b)
	}
	return a.Cmp(b)
}

// MinOutputHint produces the output of [Min] as a hint.
func MinOutputHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := inputs[0]
	b := inputs[1]
	minusOne := inputs[2]

	if cmpInField(a, b, minusOne) == -1 {
		// a < b
		results[0].Set(a)
	} else {
		// a >= b
		results[0].Set(b)
	}
	return nil
}

// IsLessOutputHint produces the output of [IsLess] as a hint.
func IsLessOutputHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := inputs[0]
	b := inputs[1]
	minusOne := inputs[2]

	if cmpInField(a, b, minusOne) == -1 {
		// a < b
		results[0].SetUint64(1)
	} else {
		// a >= b
		results[0].SetUint64(0)
	}
	return nil
}
