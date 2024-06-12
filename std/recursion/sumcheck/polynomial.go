package sumcheck

import (
	"math/big"
)

type nativePolynomial []*big.Int
type nativeMultilinear []*big.Int

// helper functions for multilinear polynomial evaluations

func fold(api *bigIntEngine, ml nativeMultilinear, r *big.Int) nativeMultilinear {
	// NB! it modifies ml in-place and also returns
	mid := len(ml) / 2
	bottom, top := ml[:mid], ml[mid:]
	var t *big.Int
	for i := 0; i < mid; i++ {
		t = api.Sub(top[i], bottom[i])
		t = api.Mul(t, r)
		bottom[i] = api.Add(bottom[i], t)
	}
	return ml[:mid]
}

func hypersumX1One(api *bigIntEngine, ml nativeMultilinear) *big.Int {
	sum := ml[len(ml)/2]
	for i := len(ml)/2 + 1; i < len(ml); i++ {
		sum = api.Add(sum, ml[i])
	}
	return sum
}

func eq(api *bigIntEngine, ml nativeMultilinear, q []*big.Int) nativeMultilinear {
	if (1 << len(q)) != len(ml) {
		panic("scalar length mismatch")
	}
	n := len(q)
	for i := range q {
		for j := 0; j < (1 << i); j++ {
			j0 := j << (n - i)
			j1 := j0 + 1<<(n-1-i)
			ml[j1] = api.Mul(q[i], ml[j0])
			ml[j0] = api.Sub(ml[j0], ml[j1])
		}
	}
	return ml
}

func eval(api *bigIntEngine, ml nativeMultilinear, r []*big.Int) *big.Int {
	mlCopy := make(nativeMultilinear, len(ml))
	for i := range mlCopy {
		mlCopy[i] = new(big.Int).Set(ml[i])
	}

	for _, ri := range r {
		mlCopy = fold(api, mlCopy, ri)
	}

	return mlCopy[0]
}

func eqAcc(api *bigIntEngine, e nativeMultilinear, m nativeMultilinear, q []*big.Int) nativeMultilinear {
	if len(e) != len(m) {
		panic("length mismatch")
	}
	if (1 << len(q)) != len(e) {
		panic("scalar length mismatch")
	}
	n := len(q)

	for i := range q {
		k := 1 << i
		for j := 0; j < k; j++ {
			j0 := j << (n - i)
			j1 := j0 + 1<<(n-1-i)

			m[j1] = api.Mul(q[i], m[j0])
			m[j0] = api.Sub(m[j0], m[j1])
		}
	}
	for i := range e {
		e[i] = api.Add(e[i], m[i])
	}
	return e
}

// func (m nonNativeMultilinear[FR]) Clone() nonNativeMultilinear[FR] {
// 	clone := make(nonNativeMultilinear[FR], len(m))
// 	for i := range m {
// 		clone[i] = new(emulated.Element[FR])
// 		*clone[i] = *m[i]
// 	}
// 	return clone
// }

// // fold fixes the value of m's first variable to at, thus halving m's required bookkeeping table size
// // WARNING: The user should halve m themselves after the call
// func (m nonNativeMultilinear[FR]) fold(api emuEngine[FR], at emulated.Element[FR]) {
// 	zero := m[:len(m)/2]
// 	one := m[len(m)/2:]
// 	for j := range zero {
// 		diff := api.Sub(one[j], zero[j])
// 		zero[j] = api.MulAcc(zero[j], diff, &at)
// 	}
// }

// // foldScaled(m, at) = fold(m, at) / (1 - at)
// // it returns 1 - at, for convenience
// func (m nonNativeMultilinear[FR]) foldScaled(api emuEngine[FR], at emulated.Element[FR]) (denom emulated.Element[FR]) {
// 	denom = *api.Sub(api.One(), &at)
// 	coeff := *api.Div(&at, &denom)
// 	zero := m[:len(m)/2]
// 	one := m[len(m)/2:]
// 	for j := range zero {
// 		zero[j] = api.MulAcc(zero[j], one[j], &coeff)
// 	}
// 	return
// }

// var minFoldScaledLogSize = 16

// // Evaluate assumes len(m) = 1 << len(at)
// // it doesn't modify m
// func (m nonNativeMultilinear[FR]) EvaluateFR(api emuEngine[FR], at []emulated.Element[FR]) emulated.Element[FR] {
// 	_m := m.Clone()

// 	/*minFoldScaledLogSize := 16
// 	if api is r1cs {
// 		minFoldScaledLogSize = math.MaxInt64  // no scaling for r1cs
// 	}*/

// 	scaleCorrectionFactor := api.One()
// 	// at each iteration fold by at[i]
// 	for len(_m) > 1 {
// 		if len(_m) >= minFoldScaledLogSize {
// 			denom := _m.foldScaled(api, at[0])
// 			scaleCorrectionFactor = api.Mul(scaleCorrectionFactor, &denom)
// 		} else {
// 			_m.fold(api, at[0])
// 		}
// 		_m = _m[:len(_m)/2]
// 		at = at[1:]
// 	}

// 	if len(at) != 0 {
// 		panic("incompatible evaluation vector size")
// 	}

// 	return *api.Mul(_m[0], scaleCorrectionFactor)
// }

// // EvalEq returns Πⁿ₁ Eq(xᵢ, yᵢ) = Πⁿ₁ xᵢyᵢ + (1-xᵢ)(1-yᵢ) = Πⁿ₁ (1 + 2xᵢyᵢ - xᵢ - yᵢ). Is assumes len(x) = len(y) =: n
// func EvalEqFR[FR emulated.FieldParams](api emuEngine[FR], x, y []emulated.Element[FR]) (eq emulated.Element[FR]) {

// 	eq = *api.One()
// 	for i := range x {
// 		next := api.Mul(&x[i], &y[i])
// 		next = api.Add(next, next)
// 		next = api.Add(next, api.One())
// 		next = api.Sub(next, &x[i])
// 		next = api.Sub(next, &y[i])

// 		eq = *api.Mul(&eq, next)
// 	}
// 	return
// }