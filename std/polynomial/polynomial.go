package polynomial

import (
	"github.com/consensys/gnark/frontend"
	"math/bits"
)

type Polynomial []frontend.Variable
type MultiLin []frontend.Variable

// Eval assumes len(m) = 1 << len(at)
func (m MultiLin) Eval(api frontend.API, at []frontend.Variable) frontend.Variable {

	eqs := make([]frontend.Variable, len(m))
	eqs[0] = 1
	for i, rI := range at {
		prevSize := 1 << i
		oneMinusRI := api.Sub(1, rI)
		for j := prevSize - 1; j >= 0; j-- {
			eqs[2*j+1] = api.Mul(rI, eqs[j])
			eqs[2*j] = api.Mul(oneMinusRI, eqs[j])
		}
	}

	evaluation := frontend.Variable(0)
	for j := range m {
		evaluation = api.Add(
			evaluation,
			api.Mul(eqs[j], m[j]),
		)
	}
	return evaluation
}

func (m MultiLin) NumVars() int {
	return bits.TrailingZeros(uint(len(m)))
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
	result := n
	n = -n
	for n++; n < -1; n++ {
		result *= n
	}
	return result
}

// computeDeltaAtNaive brute forces the computation of the δᵢ(at)
func computeDeltaAtNaive(api frontend.API, at frontend.Variable, valuesLen int) (deltaAt []frontend.Variable) {
	deltaAt = make([]frontend.Variable, valuesLen)
	atMinus := make([]frontend.Variable, valuesLen)
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
	return
}

// InterpolateLDEOnRange fits a polynomial f of degree len(values)-1 such that f(i) = values[i] whenever defined. Returns f(at)
func InterpolateLDEOnRange(api frontend.API, at frontend.Variable, values []frontend.Variable) frontend.Variable {
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
