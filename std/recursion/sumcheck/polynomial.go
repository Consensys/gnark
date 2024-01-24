package sumcheck

import "math/big"

type NativePolynomial []*big.Int
type NativeMultilinear []*big.Int

// TODO: make parametric on the engine
func fold(api *bigIntEngine, ml NativeMultilinear, r *big.Int) NativeMultilinear {
	// NB! it modifies ml in-place and also returns
	mid := len(ml) / 2
	bottom, top := ml[:mid], ml[mid:]
	t := new(big.Int)
	for i := 0; i < mid; i++ {
		api.Sub(t, top[i], bottom[i])
		api.Mul(t, t, r)
		api.Add(bottom[i], bottom[i], t)
	}
	return ml[:mid]
}

func hypesumX1One(api *bigIntEngine, ml NativeMultilinear) *big.Int {
	sum := ml[len(ml)/2]
	for i := len(ml)/2 + 1; i < len(ml); i++ {
		api.Add(sum, sum, ml[i])
	}
	return sum
}

func eq(api *bigIntEngine, ml NativeMultilinear, q []*big.Int) NativeMultilinear {
	if (1 << len(q)) != len(ml) {
		panic("scalar length mismatch")
	}
	n := len(q)
	for i := range q {
		for j := 0; j < (1 << i); j++ {
			j0 := j << (n - i)
			j1 := j0 + 1<<(n-1-i)
			api.Mul(ml[j1], q[i], ml[j0])
			api.Sub(ml[j0], ml[j0], ml[j1])
		}
	}
	return ml
}

func eqAcc(api *bigIntEngine, e NativeMultilinear, m NativeMultilinear, q []*big.Int) NativeMultilinear {
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

			api.Mul(m[j1], q[i], m[j0])
			api.Sub(m[j0], m[j0], m[j1])
		}
	}
	for i := range e {
		api.Add(e[i], e[i], m[i])
	}
	return e
}
