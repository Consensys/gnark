package sumcheck

import (
	"math/big"
	"math/bits"
)

type NativePolynomial []*big.Int
type NativeMultilinear []*big.Int

// helper functions for multilinear polynomial evaluations

func DereferenceBigIntSlice(ptrs []*big.Int) []big.Int {
	vals := make([]big.Int, len(ptrs))
	for i, ptr := range ptrs {
		vals[i] = *ptr
	}
	return vals
}

func ReferenceBigIntSlice(vals []big.Int) []*big.Int {
	ptrs := make([]*big.Int, len(vals))
	for i := range ptrs {
		ptrs[i] = &vals[i]
	}
	return ptrs
}

func Fold(api *BigIntEngine, ml NativeMultilinear, r *big.Int) NativeMultilinear {
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

func hypersumX1One(api *BigIntEngine, ml NativeMultilinear) *big.Int {
	sum := ml[len(ml)/2]
	for i := len(ml)/2 + 1; i < len(ml); i++ {
		sum = api.Add(sum, ml[i])
	}
	return sum
}

func Eq(api *BigIntEngine, ml NativeMultilinear, q []*big.Int) NativeMultilinear {
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

func Eval(api *BigIntEngine, ml NativeMultilinear, r []*big.Int) *big.Int {
	mlCopy := make(NativeMultilinear, len(ml))
	for i := range mlCopy {
		mlCopy[i] = new(big.Int).Set(ml[i])
	}

	for _, ri := range r {
		mlCopy = Fold(api, mlCopy, ri)
	}

	return mlCopy[0]
}

func eqAcc(api *BigIntEngine, e NativeMultilinear, m NativeMultilinear, q []*big.Int) NativeMultilinear {
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

func (m NativeMultilinear) NumVars() int {
	return bits.TrailingZeros(uint(len(m)))
}
