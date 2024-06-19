package polynomial

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark-crypto/utils"
)

type Polynomial []frontend.Variable
type MultiLin []frontend.Variable

var minFoldScaledLogSize = 16

func _clone(m MultiLin, p *Pool) MultiLin {
	if p == nil {
		return m.Clone()
	} else {
		return p.Clone(m)
	}
}

func _dump(m MultiLin, p *Pool) {
	if p != nil {
		p.Dump(m)
	}
}

// Evaluate assumes len(m) = 1 << len(at)
// it doesn't modify m
func (m MultiLin) EvaluatePool(api frontend.API, at []frontend.Variable, pool *Pool) frontend.Variable {
	_m := _clone(m, pool)

	/*minFoldScaledLogSize := 16
	if api is r1cs {
		minFoldScaledLogSize = math.MaxInt64  // no scaling for r1cs
	}*/

	scaleCorrectionFactor := frontend.Variable(1)
	// at each iteration fold by at[i]
	for len(_m) > 1 {
		if len(_m) >= minFoldScaledLogSize {
			scaleCorrectionFactor = api.Mul(scaleCorrectionFactor, _m.foldScaled(api, at[0]))
		} else {
			_m.Fold(api, at[0])
		}
		_m = _m[:len(_m)/2]
		at = at[1:]
	}

	if len(at) != 0 {
		panic("incompatible evaluation vector size")
	}

	result := _m[0]

	_dump(_m, pool)

	return api.Mul(result, scaleCorrectionFactor)
}

// Evaluate assumes len(m) = 1 << len(at)
// it doesn't modify m
func (m MultiLin) Evaluate(api frontend.API, at []frontend.Variable) frontend.Variable {
	_m := m.Clone()

	/*minFoldScaledLogSize := 16
	if api is r1cs {
		minFoldScaledLogSize = math.MaxInt64  // no scaling for r1cs
	}*/

	scaleCorrectionFactor := frontend.Variable(1)
	// at each iteration fold by at[i]
	for len(_m) > 1 {
		if len(_m) >= minFoldScaledLogSize {
			scaleCorrectionFactor = api.Mul(scaleCorrectionFactor, _m.foldScaled(api, at[0]))
		} else {
			_m.Fold(api, at[0])
		}
		_m = _m[:len(_m)/2]
		at = at[1:]
	}

	if len(at) != 0 {
		panic("incompatible evaluation vector size")
	}

	return api.Mul(_m[0], scaleCorrectionFactor)
}

// fold fixes the value of m's first variable to at, thus halving m's required bookkeeping table size
// WARNING: The user should halve m themselves after the call
func (m MultiLin) Fold(api frontend.API, at frontend.Variable) {
	zero := m[:len(m)/2]
	one := m[len(m)/2:]
	for j := range zero {
		diff := api.Sub(one[j], zero[j])
		zero[j] = api.MulAcc(zero[j], diff, at)
	}
}

func (m *MultiLin) FoldParallel(api frontend.API, r frontend.Variable) utils.Task {
	mid := len(*m) / 2
	bottom, top := (*m)[:mid], (*m)[mid:]

	*m = bottom

	return func(start, end int) {
		var t frontend.Variable // no need to update the top part
		for i := start; i < end; i++ {
			// table[i] ← table[i]  + r (table[i + mid] - table[i])
			t = api.Sub(&top[i], &bottom[i])
			t = api.Mul(&t, &r)
			bottom[i] = api.Add(&bottom[i], &t)
		}
	}
}

// Eq sets m to the representation of the polynomial Eq(q₁, ..., qₙ, *, ..., *) × m[0]
func (m *MultiLin) Eq(api frontend.API, q []frontend.Variable) {
	n := len(q)

	if len(*m) != 1<<n {
		panic("destination must have size 2 raised to the size of source")
	}

	//At the end of each iteration, m(h₁, ..., hₙ) = Eq(q₁, ..., qᵢ₊₁, h₁, ..., hᵢ₊₁)
	for i := range q { // In the comments we use a 1-based index so q[i] = qᵢ₊₁
		// go through all assignments of (b₁, ..., bᵢ) ∈ {0,1}ⁱ
		for j := 0; j < (1 << i); j++ {
			j0 := j << (n - i)                 // bᵢ₊₁ = 0
			j1 := j0 + 1<<(n-1-i)              // bᵢ₊₁ = 1
			(*m)[j1] = api.Mul((*m)[j1], q[i])     // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 1) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) qᵢ₊₁
			(*m)[j0] = api.Sub((*m)[j0], (*m)[j1]) // Eq(q₁, ..., qᵢ₊₁, b₁, ..., bᵢ, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) Eq(qᵢ₊₁, 0) = Eq(q₁, ..., qᵢ, b₁, ..., bᵢ) (1-qᵢ₊₁)
		}
	}
}

// foldScaled(m, at) = fold(m, at) / (1 - at)
// it returns 1 - at, for convenience
func (m MultiLin) foldScaled(api frontend.API, at frontend.Variable) (denom frontend.Variable) {
	denom = api.Sub(1, at)
	coeff := api.Div(at, denom)
	zero := m[:len(m)/2]
	one := m[len(m)/2:]
	for j := range zero {
		zero[j] = api.MulAcc(zero[j], one[j], coeff)
	}
	return
}

func (m MultiLin) NumVars() int {
	return bits.TrailingZeros(uint(len(m)))
}

func (m MultiLin) Clone() MultiLin {
	clone := make(MultiLin, len(m))
	copy(clone, m)
	return clone
}

func (p Polynomial) Eval(api frontend.API, at frontend.Variable) (pAt frontend.Variable) {
	pAt = 0

	for i := len(p) - 1; i >= 0; i-- {
		pAt = api.Add(pAt, p[i])
		if i != 0 {
			pAt = api.Mul(pAt, at)
		}
	}

	return
}

// negFactorial returns (-n)(-n+1)...(-2)(-1)
// There are more efficient algorithms, but we are talking small values here so it doesn't matter
func negFactorial(n int) int {
	n = -n
	result := n
	for n++; n <= -1; n++ {
		result *= n
	}
	return result
}

// computeDeltaAtNaive brute forces the computation of the δᵢ(at)
func computeDeltaAtNaive(api frontend.API, at frontend.Variable, valuesLen int) []frontend.Variable {
	deltaAt := make([]frontend.Variable, valuesLen)
	atMinus := make([]frontend.Variable, valuesLen) //TODO: No need for this array and the following loop
	for i := range atMinus {
		atMinus[i] = api.Sub(at, i)
	}
	factInv := api.Inverse(negFactorial(valuesLen - 1))

	for i := range deltaAt {
		deltaAt[i] = factInv
		for j := range atMinus {
			if i != j {
				deltaAt[i] = api.Mul(deltaAt[i], atMinus[j])
			}
		}

		if i+1 < len(deltaAt) {
			factAdjustment := api.DivUnchecked(i+1-valuesLen, i+1)
			factInv = api.Mul(factAdjustment, factInv)
		}
	}
	return deltaAt
}

// InterpolateLDE fits a polynomial f of degree len(values)-1 such that f(i) = values[i] whenever defined. Returns f(at)
func InterpolateLDE(api frontend.API, at frontend.Variable, values []frontend.Variable) frontend.Variable {
	deltaAt := computeDeltaAtNaive(api, at, len(values))

	res := frontend.Variable(0)

	for i, c := range values {
		res = api.Add(res,
			api.Mul(c, deltaAt[i]),
		)
	}

	return res
}

// EvalEq returns Πⁿ₁ Eq(xᵢ, yᵢ) = Πⁿ₁ xᵢyᵢ + (1-xᵢ)(1-yᵢ) = Πⁿ₁ (1 + 2xᵢyᵢ - xᵢ - yᵢ). Is assumes len(x) = len(y) =: n
func EvalEq(api frontend.API, x, y []frontend.Variable) (eq frontend.Variable) {

	eq = 1
	for i := range x {
		next := api.Mul(x[i], y[i])
		next = api.Add(next, next)
		next = api.Add(next, 1)
		next = api.Sub(next, x[i])
		next = api.Sub(next, y[i])

		eq = api.Mul(eq, next)
	}
	return
}
