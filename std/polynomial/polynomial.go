package polynomial

import (
	"github.com/consensys/gnark/frontend"
	"math/bits"
)

type Polynomial []frontend.Variable //TODO: Is there already such a data structure?
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

	evaluation := frontend.Variable(0) //TODO: Does the API ignore publicly adding 0 to something?
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
	pAt = 0 //TODO: Dummy add

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

// InterpolateLDEOnRange fits a polynomial f of degree len(values)-1 such that f(i) = values[i] whenever defined. Returns f(at)
// Algorithm taken from https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf section 2.4
func InterpolateLDEOnRange(api frontend.API, at frontend.Variable, values []frontend.Variable) frontend.Variable {
	deltaAt := make([]frontend.Variable, len(values))
	deltaAt[0] = api.Inverse(negFactorial(len(values) - 1))
	for k := 1; k < len(values); k++ {
		deltaAt[0] = api.Mul(deltaAt[0], api.Sub(at, k))
	}

	// Now recursively compute δᵢ(at) by noting it is equal to δᵢ(at) × (r-i+1) × (r-i)⁻¹ × i⁻¹ × (-len(values)+i)
	for i := 1; i < len(values); i++ {
		// @gbotrel Is it important to write shallow circuits, or does the compiler rearrange things for you?
		// Is it important to cache inverses of numbers, or does the compiler do that for you?
		removeFromNumeratorAddToDenominator := api.Mul(i, api.Sub(at, i))
		removeFromDenominatorAddToNumerator := api.Mul(api.Sub(at, i-1), i-len(values))
		adjustment := api.DivUnchecked(removeFromDenominatorAddToNumerator, removeFromNumeratorAddToDenominator) //TODO: May be shallower to mul removeFromDenominator and δᵢ₋₁ first and THEN divide
		deltaAt[i] = api.Mul(deltaAt[i-1], adjustment)
	}

	var res frontend.Variable
	res = 0 // @gbotrel: does the API know x ↦ 0+x is a no-op?

	for i, c := range values {
		res = api.Add(res,
			api.Mul(c, deltaAt[i]),
		)
	}

	return res
}

// EvalEq returns Πⁿ₁ Eq(xᵢ, yᵢ) = Πⁿ₁ xᵢyᵢ + (1-xᵢ)(1-yᵢ) = Πⁿ₁ (1 + 2xᵢyᵢ - xᵢ - yᵢ). Is assumes len(x) = len(y) =: n
func EvalEq(api frontend.API, x, y []frontend.Variable) (eq frontend.Variable) {

	eq = 1 //@TODO: Does the compiler know a-priori that 1 * a = a?
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
