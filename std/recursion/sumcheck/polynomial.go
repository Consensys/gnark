package sumcheck

import "math/big"

type NativePolynomial []*big.Int
type NativeMultilinear []*big.Int

func fold(api *bigIntEngine, ml NativeMultilinear, r *big.Int) []*big.Int {
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
