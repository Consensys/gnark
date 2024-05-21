package sumcheck

import "github.com/consensys/gnark/frontend"

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

// InterpolateOnRange fits a polynomial f of degree len(values)-1 such that f(i) = values[i] whenever defined. Returns f(at)
// Algorithm taken from https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf section 2.4
func InterpolateOnRange(api frontend.API, at frontend.Variable, values ...frontend.Variable) frontend.Variable {
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
